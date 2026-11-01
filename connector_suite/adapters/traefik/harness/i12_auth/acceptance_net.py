"""Bounded physical client/backend/authorization/UDS fixtures, no qualification."""
import argparse
from dataclasses import dataclass
import hashlib
import http.client
from http import HTTPStatus
from email.message import Message
from email.utils import formatdate
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import struct
import sys
import threading
import time

MAX_BYTES=4*1024*1024
MAX_RESPONSE_BYTES=16*1024*1024
WRITE_LOCK=threading.Lock()
PRIVATE_HEADERS=('x-msconnector-trusted-reservation','x-msconnector-response-handle')
AUTH_LOG='authorization.jsonl'
PEER_LOG='companion-peer.jsonl'
HTTP_VERSION='HTTP/1.1'


def loopback_port(port):
 if type(port) is not int or not 1<=port<=65535:raise ValueError('bounded loopback port required')
 return port


def origin_path(path):
 # HTTPConnection accepts absolute-form URLs; the relay only permits local
 # origin-form targets, with no authority, control bytes, or backslash aliases.
 if not isinstance(path,str) or not path.startswith('/') or path.startswith('//'):
  raise ValueError('origin-form HTTP target required')
 if any(ord(char)<33 or ord(char)==127 or char=='\\' for char in path):
  raise ValueError('invalid origin-form HTTP target')
 return path


def loopback_connection(port,timeout):
 return http.client.HTTPConnection('127.0.0.1',loopback_port(port),timeout=timeout)


def client_connection(port,timeout):
 connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 try:
  connection.settimeout(timeout)
  connection.connect(('127.0.0.1',loopback_port(port)))
 except (OSError,ValueError):
  connection.close();raise
 return connection


class LoopbackEvidenceServer(socketserver.ThreadingMixIn,socketserver.BaseServer):
 """Plain HTTP is the measured host protocol inside the admitted namespace.

 The fixture cannot bind an external interface or select a DNS hostname.
 """
 daemon_threads=True
 def __init__(self,port,handler):
  self.server_name='127.0.0.1';self.server_port=loopback_port(port)
  address=('127.0.0.1',self.server_port)
  super().__init__(address,handler)
  # Own the transport here: there is no configurable server bind address,
  # hostname resolution, external listener, or optional TLS downgrade.
  self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  try:
   self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   self.socket.bind(address)
   self.socket.listen(5)
  except OSError:
   self.socket.close();raise

 def fileno(self):return self.socket.fileno()

 def get_request(self):return self.socket.accept()

 def shutdown_request(self,request):
  try:request.shutdown(socket.SHUT_WR)
  except OSError:pass # A reset or disconnected peer already ended its write side.
  finally:request.close()

 def server_close(self):
  self.socket.close()
  super().server_close()


def dispatch_private_http(server,request,address):
 """Transfer each accepted socket to exactly one worker or close it."""
 try:
  if server.verify_request(request,address):server.process_request(request,address)
  else:server.shutdown_request(request)
 except Exception:
  try:server.handle_error(request,address)
  finally:server.shutdown_request(request)
 except (SystemExit,KeyboardInterrupt):
  server.shutdown_request(request);raise


def serve_private_http(server):
 """Accept only on the fixture-owned listener until process termination.

 ThreadingMixIn owns worker dispatch and each worker's final socket shutdown.
 SIGTERM raises SystemExit in the main thread, including during accept; the
 finalizer closes the listener and invokes ThreadingMixIn's worker cleanup.
 """
 try:
  while True:
   try:request,address=server.get_request()
   except OSError:
    time.sleep(0.01);continue
   dispatch_private_http(server,request,address)
 finally:server.server_close()


class EvidenceRequestHandler(socketserver.StreamRequestHandler):
 """One bounded HTTP/1.x connection, retaining duplicate header field order.

 The body readers below own entity framing. This layer only parses the head
 and writes HTTP bytes on the fixed private loopback listener.
 """
 timeout=15
 protocol_version=HTTP_VERSION
 evidence_log=AUTH_LOG
 def handle(self):
  self.close_connection=True
  try:
   while True:
    self.raw_requestline=b''
    self.raw_requestline=self.rfile.readline(65537)
    if not self.raw_requestline:return
    if not self.parse_request():
     self.failure_receipt('http_request_rejected','InvalidHead');return
    method=getattr(self,'do_'+self.command,None)
    if method is None:self.send_error(501)
    else:method()
    self.wfile.flush()
    if self.close_connection:return
  except (OSError,ValueError) as error:
   self.failure_receipt('http_connection_error',type(error).__name__)
   self.close_connection=True

 def failure_receipt(self,event,error):
  dump(self.root,self.evidence_log,dict(stamp(),event=event,error=error,request_line_bytes=len(self.raw_requestline)))

 def parse_request(self):
  self.headers=Message();self.command=None;self.path=None;self.close_connection=True
  try:
   self.parse_request_line()
   self.parse_headers()
   connection={token.strip().lower() for value in self.headers.get_all('Connection',[]) for token in value.split(',')}
   self.close_connection=self.request_version=='HTTP/1.0'
   if 'close' in connection:self.close_connection=True
   elif 'keep-alive' in connection:self.close_connection=False
   expectation=self.headers.get('Expect','')
   if expectation:
    if expectation.lower()!='100-continue':self.send_error(417);return False
    self.wfile.write((HTTP_VERSION+' 100 Continue\r\n\r\n').encode('ascii'))
   return True
  except ValueError:
   self.send_error(400,'invalid HTTP request head');return False

 def parse_request_line(self):
  if len(self.raw_requestline)>65536 or not self.raw_requestline.endswith(b'\r\n'):
   raise ValueError('bounded CRLF request line required')
  line=self.raw_requestline[:-2].decode('ascii')
  match=re.fullmatch(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([^ ]+) (HTTP/1\.[01])",line)
  if match is None:raise ValueError('HTTP/1.x request line required')
  self.command,self.path,self.request_version=match.groups()
  origin_path(self.path)

 def parse_headers(self):
  total=len(self.raw_requestline)
  for _ in range(101):
   line=self.rfile.readline(65537);total+=len(line)
   if total>65536 or not line.endswith(b'\r\n'):raise ValueError('bounded CRLF headers required')
   if line==b'\r\n':return
   key,separator,value=line[:-2].partition(b':')
   if not separator or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+",key) is None:
    raise ValueError('HTTP field name required')
   if any(byte<32 and byte!=9 or byte==127 for byte in value):raise ValueError('invalid HTTP field value')
   self.headers[key.decode('ascii')]=value.decode('latin1').strip(' \t')
  raise ValueError('bounded HTTP header count exceeded')

 def send_response(self,code,message=None):
  if type(code) is not int or not 100<=code<=999:raise ValueError('three-digit HTTP status required')
  reason=http.client.responses.get(code,'') if message is None else message
  if any(ord(char)<32 or ord(char)==127 for char in reason):raise ValueError('invalid HTTP reason phrase')
  self._response_head=[f'{self.protocol_version} {code} {reason}\r\n'.encode('latin1')]
  self.send_header('Server','BaseHTTP/0.6 Python/'+sys.version.split()[0])
  self.send_header('Date',formatdate(usegmt=True))

 def send_header(self,key,value):
  if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",key) is None or any(ord(char)<32 and char!='\t' or ord(char)==127 for char in value):
   raise ValueError('invalid HTTP response field')
  self._response_head.append((key+': '+value+'\r\n').encode('latin1'))
  if key.lower()=='connection':self.close_connection=value.lower()!='keep-alive'

 def end_headers(self):
  self.wfile.write(b''.join(self._response_head)+b'\r\n');self._response_head=[]

 def send_error(self,code,message=None):
  status=HTTPStatus(code);payload=(str(code)+' '+status.phrase+'\n').encode('ascii')
  self.send_response(code,message)
  self.send_header('Content-Type','text/plain; charset=utf-8')
  self.send_header('Content-Length',str(len(payload)));self.send_header('Connection','close');self.end_headers()
  if self.command!='HEAD':self.wfile.write(payload)


def private_header_receipt(headers):
 pairs=list(headers)
 return {name:{'count':sum(key.lower()==name for key,_ in pairs),
  'all_values_valid_64hex':all(re.fullmatch(r'[0-9a-f]{64}',value) is not None for key,value in pairs if key.lower()==name),
  'absent':not any(key.lower()==name for key,_ in pairs)} for name in PRIVATE_HEADERS}


def redact_headers(headers):
 return [[key,'[REDACTED]' if key.lower() in PRIVATE_HEADERS else value] for key,value in headers]

def dump(root,name,value):
 with WRITE_LOCK, (root/name).open('a') as stream:
  stream.write(json.dumps(value,separators=(',',':'))+'\n')
def stamp():return {'pid':os.getpid(),'monotonic_ns':time.monotonic_ns(),'wall_ns':time.time_ns()}
def sha(value):return hashlib.sha256(value).hexdigest()
def body(value):return bytes.fromhex(value['body_hex'])
def segments(data,lengths):
 offset=0
 for size in lengths:
  if size<0:raise ValueError('negative fixture chunk')
  if size:yield data[offset:offset+size]
  offset+=size
 if offset<len(data):yield data[offset:]
 if offset>len(data):raise ValueError('fixture chunks exceed body')
def wait_barrier(path,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if path.exists():return True
  time.sleep(0.01)
 return False

def handler_record(handler,event,**fields):
 dump(handler.root,'backend.jsonl',dict(stamp(),event=event,peer=list(handler.client_address),**fields))

def traffic_label(probe,base_probe,neighbor):
 match=re.fullmatch(re.escape(base_probe)+r'-ready-(\d)-neighbor',probe,flags=re.ASCII)
 if match:return 'readiness-'+match[1]
 match=re.fullmatch(re.escape(base_probe)+r'-seq-([0-2])',probe)
 if match:return 'sequence-'+match[1]
 if neighbor:return 'neighbor'
 if probe.endswith('-sink-positive'):return 'positive'
 return 'target'


class BackendBodyError(ValueError):
 def __init__(self,message,entity,wire,receipt):
  super().__init__(message);self.entity=bytes(entity);self.wire=bytes(wire);self.receipt=receipt


def read_backend_body(stream,headers,maximum=MAX_BYTES,trailing_check=None):
 """Decode one already-header-parsed request; retain physical wire on failure."""
 entity=bytearray();wire=bytearray();receipt={'complete':False,'http_eos':False,'chunks':[]}
 if type(maximum) is not int or not 0<=maximum<=MAX_BYTES:raise ValueError('bounded backend request required')
 def exact(size,body_data=False):
  part=stream.read(size);wire.extend(part)
  if body_data:entity.extend(part)
  if len(part)!=size:raise ValueError('incomplete backend request body')
  return part
 try:
  lengths=headers.get_all('Content-Length',[]);encodings=headers.get_all('Transfer-Encoding',[])
  validate_backend_framing(lengths,encodings)
  if encodings:
   if encodings!=['chunked']:raise ValueError('unsupported backend transfer coding')
   receipt['framing']='chunked'
   read_backend_chunks(stream,maximum,entity,wire,receipt,exact)
  elif lengths:
   read_backend_length(lengths[0],maximum,receipt,exact)
  else:receipt.update(framing='no-body',declared=0,http_eos=True)
  if trailing_check is not None and trailing_check():raise ValueError('trailing bytes after backend request body')
  receipt['complete']=True
 except (ValueError,OSError) as error:
  receipt.update(error={'type':type(error).__name__,'message':str(error)},entity_bytes=len(entity),
   entity_sha256=sha(entity),wire_bytes=len(wire),wire_sha256=sha(wire))
  raise BackendBodyError(str(error),entity,wire,receipt) from error
 receipt.update(entity_bytes=len(entity),entity_sha256=sha(entity),wire_bytes=len(wire),wire_sha256=sha(wire))
 return bytes(entity),bytes(wire),receipt


def read_backend_chunks(stream,maximum,entity,wire,receipt,exact):
 while True:
  if len(receipt['chunks'])>=65536 or len(wire)>maximum*2+65536:raise ValueError('bounded backend chunk framing exceeded')
  line=stream.readline(128);wire.extend(line)
  if not re.fullmatch(rb'[0-9a-fA-F]{1,8}\r\n',line):raise ValueError('invalid backend chunk size')
  size=int(line[:-2],16)
  if size>maximum-len(entity):raise ValueError('bounded backend body exceeded')
  if size==0:
   if exact(2)!=b'\r\n':raise ValueError('backend chunk trailers forbidden')
   receipt['http_eos']=True;return
  offset=len(entity);part=exact(size,True)
  if exact(2)!=b'\r\n':raise ValueError('invalid backend chunk end')
  receipt['chunks'].append({'offset':offset,'bytes':len(part),'sha256':sha(part)})


class BackendHeaderReader:
 def __init__(self,stream):self.stream=stream;self.wire=bytearray()
 def readline(self,limit):
  line=self.stream.readline(min(limit,65537));self.wire.extend(line)
  if len(self.wire)>65536:raise ValueError('bounded backend headers exceeded')
  return line


def backend_pending_bytes(handler):
 # A nonblocking peek observes already-buffered bytes as well as socket bytes.
 # It neither consumes another request nor waits for a TCP end as an EOS proxy.
 timeout=handler.connection.gettimeout();handler.connection.setblocking(False)
 try:return bool(handler.rfile.peek(1))
 except BlockingIOError:return False
 finally:handler.connection.settimeout(timeout)


def redacted_backend_head(raw):
 lines=raw.split(b'\r\n');private=False
 for index,line in enumerate(lines[1:],1):
  if line.startswith((b' ',b'\t')) and private:
   lines[index]=b' [REDACTED]';continue
  name,separator,_=line.partition(b':')
  private=bool(separator and name.decode('latin1').lower() in PRIVATE_HEADERS)
  if private:lines[index]=name+b': [REDACTED]'
 return b'\r\n'.join(lines)

class Backend(EvidenceRequestHandler):
 protocol_version=HTTP_VERSION
 evidence_log='backend.jsonl'
 def setup(self):
  super().setup();handler_record(self,'accepted_connection')
 def parse_request(self):
  original=self.rfile;reader=BackendHeaderReader(original);self.rfile=reader
  try:result=super().parse_request()
  except ValueError:
   self.send_error(400,'invalid backend headers');self.close_connection=True;result=False
  finally:self.rfile=original
  self.request_head_wire=self.raw_requestline+bytes(reader.wire)
  handler_record(self,'parsed_headers',parse_success=result,raw_request_line_hex=self.raw_requestline.hex(),
   request_head_wire_bytes=len(self.request_head_wire),request_head_wire_sha256=sha(self.request_head_wire),
   probe=self.headers.get('X-I12-Probe') if result else None,
   method=getattr(self,'command',None),uri=getattr(self,'path',None),
   headers=redact_headers(self.headers.raw_items()) if result else [],
   private_headers=private_header_receipt(self.headers.raw_items()) if result else None)
  return result
 def do_HEAD(self):self.respond()
 def do_PATCH(self):self.respond()
 def do_GET(self):self.respond()
 def do_POST(self):self.respond()
 def do_DELETE(self):self.respond()
 def do_PUT(self):self.respond()
 def respond(self):
  probe=self.headers.get('X-I12-Probe','');neighbor=self.headers.get('X-I12-Neighbor')=='1'
  handler_record(self,'handler_entry_before_body',probe=probe,uri=self.path,method=self.command)
  suffix=traffic_label(probe,self.spec['probe_id'],neighbor)
  raw_head=self.request_head_wire
  redacted_head=redacted_backend_head(raw_head)
  (self.root/('backend-'+suffix+'.request-head.raw')).write_bytes(redacted_head)
  physical=self.spec['fixture'].get('physical_file_supplement',{})
  target_file=(physical.get('direction')=='request' and probe==self.spec['probe_id'] and not neighbor)
  if target_file and (physical.get('schema')!='traefik-auth-physical-file-http-v1' or
      self.headers.get_all('X-I12-Acceptance-Key',[])!=[probe] or self.headers.get_all('X-Request-Id',[])!=[probe]):
   handler_record(self,'physical_file_correlation_rejected',probe=probe,request_head_wire_sha256=sha(raw_head))
   self.send_error(400,'physical file correlation differs');self.close_connection=True;return
  data=b'';wire=b''
  try:
   data,wire,framing=read_backend_body(self.rfile,self.headers,
    trailing_check=(lambda:backend_pending_bytes(self)) if target_file or self.headers.get_all('Transfer-Encoding') else None)
  except BackendBodyError as error:
   data,wire,framing=error.entity,error.wire,error.receipt
   body_path=self.root/f'backend-{suffix}.request-body.raw'
   body_path.write_bytes(data)
   wire_path=self.root/f'backend-{suffix}.request-body-wire.raw'
   wire_path.write_bytes(wire)
   handler_record(self,'request_body',probe=probe,actual_bytes=len(data),sha256=sha(data),complete=False,framing=framing)
   self.send_error(400,'invalid backend request framing');self.close_connection=True;return
  try:
   if target_file:
    expected=physical['files'][physical['fixture']]
    framing['physical_file_expected']={'size':expected['size'],'sha256':expected['sha256']}
    framing['physical_file_exact_match']=len(data)==expected['size'] and sha(data)==expected['sha256']
   handler_record(self,'request_body',probe=probe,declared=framing.get('declared'),actual_bytes=len(data),sha256=sha(data),
    complete=framing['complete'],framing=framing,request_head_wire_sha256=sha(raw_head),
    request_head_private_values_redacted=redacted_head!=raw_head)
   (self.root/('backend-'+suffix+'.request-body.raw')).write_bytes(data)
   (self.root/('backend-'+suffix+'.request-body-wire.raw')).write_bytes(wire)
   if target_file and not framing['physical_file_exact_match']:
    self.send_error(400,'physical file entity differs');self.close_connection=True;return
   self.write_response(probe,neighbor,suffix)
  except (OSError,ValueError) as error:
   handler_record(self,'handler_exception',probe=probe,error=type(error).__name__,request_bytes_read=len(data));self.close_connection=True
 def write_response(self,probe,neighbor,suffix):
   fixture=self.spec['fixture']['backend']
   payload=b'i12-neighbor-ok\n' if neighbor else body(fixture)
   headers=[['Content-Type','text/plain']] if neighbor else fixture['headers']
   self.send_response(200 if neighbor else fixture['status'])
   for key,value in headers:self.send_header(key,value)
   self.send_header('Content-Length',str(len(payload)));self.send_header('Connection','keep-alive' if self.headers.get('Connection','').lower()=='keep-alive' else 'close');self.end_headers()
   handler_record(self,'response_headers_return',probe=probe,status=200 if neighbor else fixture['status'],declared_bytes=len(payload))
   written=0
   lengths=[len(payload)] if neighbor else fixture.get('chunk_lengths',[len(payload)])
   for chunk in segments(payload,lengths):
    chunk=backend_chunk(chunk,fixture,neighbor,written)
    if not chunk:break
    count=self.wfile.write(chunk);self.wfile.flush();written+=count
    handler_record(self,'body_write_return',probe=probe,bytes=count,total=written)
    if not neighbor and not self.response_barriers(fixture,probe,written,len(payload)):break
    time.sleep(0.025)
   handler_record(self,'response_end',probe=probe,written=written,declared=len(payload),complete=written==len(payload))
   (self.root/('backend-'+suffix+'.response-body.raw')).write_bytes(payload[:written])
   if not neighbor and fixture.get('truncate_after_bytes') is not None:self.close_connection=True
 def response_barriers(self,fixture,probe,written,total):
  barrier=fixture.get('barrier_after_bytes')
  if barrier and written>=barrier and written<total:
   (self.root/'backend-paused').write_text(str(time.monotonic_ns()))
   released=wait_barrier(self.root/'client-first-entity')
   handler_record(self,'causal_barrier',probe=probe,released_by_actual_client=released,response_finished=False,bytes_sent=written)
   if not released:return False
  if fixture.get('wait_for_client_termination') and written>=8192 and written<total:
   released=wait_barrier(self.root/'client-signal-reaped')
   handler_record(self,'waited_actual_client_reap',probe=probe,released=released,bytes_sent=written)
   return released
  return True
 def log_message(self,*_):
  # Structured physical receipts own fixture logging.
  return

class Relay(EvidenceRequestHandler):
 protocol_version=HTTP_VERSION
 def do_HEAD(self):self.forward()
 def do_PATCH(self):self.forward()
 def do_GET(self):self.forward()
 def do_POST(self):self.forward()
 def do_DELETE(self):self.forward()
 def do_PUT(self):self.forward()
 def forward(self):
  self.forward_headers=[]
  if self.path!='/authorize':self.send_error(404);return
  probe=self.headers.get('X-I12-Probe','');neighbor=self.headers.get('X-I12-Neighbor')=='1';name=traffic_label(probe,self.spec['probe_id'],neighbor)
  length=int(self.headers.get('Content-Length','0'))
  if not 0<=length<=MAX_BYTES:self.send_error(400);return
  received=self.rfile.read(length);authorization_sample_path(self.root,name).write_bytes(received)
  record=dict(stamp(),event='authorization_sample',probe=probe,method=self.command,uri=self.path,
   headers=redact_headers(self.headers.raw_items()),private_headers=private_header_receipt(self.headers.raw_items()),
   declared=length,actual_bytes=len(received),sha256=sha(received))
  dump(self.root,AUTH_LOG,record)
  upstream=loopback_connection(self.engine_port,timeout=12)
  try:
   # The host's forwardAuth URL is fixed; the original request URI remains in
   # X-Forwarded-Uri. Incoming paths cannot select another native service API.
   upstream.putrequest(self.command,'/authorize',skip_host=True,skip_accept_encoding=True)
   for key,value in self.headers.raw_items():
    if key.lower() not in ('transfer-encoding','connection'):upstream.putheader(key,value)
   upstream.putheader('Connection','close');upstream.endheaders()
   for chunk in segments(received,[len(received)] if neighbor else self.spec['fixture']['request'].get('chunk_lengths',[len(received)])):
    upstream.send(chunk);dump(self.root,AUTH_LOG,dict(stamp(),event='engine_body_write_return',probe=probe,bytes=len(chunk)));time.sleep(0.015)
   response=upstream.getresponse();payload=response.read(65537)
   if len(payload)>65536:raise ValueError('authorization response bound exceeded')
   native={'status':response.status,'body_bytes':len(payload),'body_sha256':sha(payload)}
   dump(self.root,AUTH_LOG,dict(stamp(),event='native_authorization_response',probe=probe,**native))
   self.relay_response(response,payload,probe,neighbor,native)
  except Exception as error:
   dump(self.root,AUTH_LOG,dict(stamp(),event='relay_error',probe=probe,error=type(error).__name__))
   # The host applies its own transport-error status; no response is invented.
   self.close_connection=True
  finally:upstream.close();self.close_connection=True
 def relay_response(self,response,payload,probe,neighbor,native):
   headers=list(response.getheaders());options={} if neighbor else self.spec['fixture'].get('relay',{})
   dump(self.root,AUTH_LOG,dict(stamp(),event='native_authorization_private_headers',probe=probe,
    private_headers=private_header_receipt(headers)))
   handle=next((value for key,value in headers if key.lower()=='x-msconnector-response-handle'),None)
   mode=options.get('handle')
   if mode=='expired':
    dump(self.root,AUTH_LOG,dict(stamp(),event='preclaim_delay_start',probe=probe,seconds=5.3));time.sleep(5.3)
   self.buffer_response_headers(headers,mode,handle)
   size=options.get('authorization_body_size')
   if size is not None:payload=b'i'*size
   self.send_response(response.status)
   for key,value in getattr(self,'forward_headers',[]):self.send_header(key,value)
   self.send_header('Content-Length',str(len(payload)));self.send_header('Connection','close');self.end_headers();self.wfile.write(payload);self.wfile.flush()
   dump(self.root,AUTH_LOG,dict(stamp(),event='relay_response_write_return',probe=probe,
    status=response.status,body_bytes=len(payload),native_response=native,handle_mode=mode,synthetic_body=size is not None))
 def buffer_response_headers(self,headers,mode,handle):
   for key,value in headers:
    value=relay_header_value(key,value,mode,handle)
    if value is None:continue
    if key.lower() not in ('content-length','transfer-encoding','connection'):self.send_header_buffered(key,value)

 def send_header_buffered(self,key,value):
  if not hasattr(self,'forward_headers'):self.forward_headers=[]
  self.forward_headers.append((key,value))
 def log_message(self,*_):
  # Structured authorization receipts replace uncorrelated stderr messages.
  return


def request_headers(spec,neighbor,sequence_kind,headers,probe,payload):
 fixture=spec['fixture']
 if sequence_kind=='deny':headers.append(['X-Modsec-Smoke','block'])
 elif sequence_kind=='allow':headers=[h for h in headers if h[0].lower()!='x-modsec-smoke']
 if not any(key.lower()=='host' for key,_ in headers):headers.append(['Host','example.test'])
 headers.append(['X-I12-Probe',probe])
 if neighbor:headers.extend([['X-I12-Neighbor','1'],['X-Request-Id',probe],['X-Modsec-Transaction-Id',probe]])
 else:add_transaction_header(spec,headers,probe)
 if not any(key.lower()=='content-length' for key,_ in headers):headers.append(['Content-Length',str(len(payload))])
 if not any(key.lower()=='connection' for key,_ in headers):headers.append(['Connection','keep-alive' if fixture.get('client',{}).get('keepalive') and not neighbor else 'close'])
 return headers


def raw_request(spec,neighbor=False,sequence_kind=None):
 fixture=spec['fixture'];request=fixture['request'];probe=spec['probe_id']+('-neighbor' if neighbor else '')
 method='GET' if neighbor else request['method'];uri='/i12/neighbor' if neighbor else request['uri']
 headers=[] if neighbor else copy_headers(request['headers'])
 payload=b'' if neighbor else body(request)
 headers=request_headers(spec,neighbor,sequence_kind,headers,probe,payload)
 head=(method+' '+uri+' HTTP/1.1\r\n'+''.join(key+': '+value+'\r\n' for key,value in headers)+'\r\n').encode('iso-8859-1')
 raw=fixture.get('client',{}).get('raw_template') if not neighbor else None
 if raw:return malformed_request(method,uri,probe,raw)

 return head,payload,[len(payload)] if neighbor else request.get('chunk_lengths',[len(payload)])
def malformed_request(method,uri,probe,raw):
 prefix=(method+' '+uri+' HTTP/1.1\r\nHost: example.test\r\nX-I12-Probe: ').encode('iso-8859-1')+probe.encode()+b'\r\n'
 suffix={'invalid_content_length':b'Content-Length: nope\r\n','conflicting_content_length':b'Content-Length: 1\r\nContent-Length: 2\r\n','duplicate_transfer_encoding':b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n','content_length_overflow':b'Content-Length: 184467440737095516160\r\n'}[raw]
 framing_end=b'0\r\n\r\n' if raw=='duplicate_transfer_encoding' else b''
 return prefix+suffix+b'Connection: close\r\n\r\n'+framing_end,b'',[]

def copy_headers(headers):return [list(pair) for pair in headers]


def framing(raw):
 if b'\r\n\r\n' not in raw:return {'complete':False,'entity_bytes':0,'status':None}
 head,entity=raw.split(b'\r\n\r\n',1)
 lines=head.split(b'\r\n');status=int(lines[0].split()[1]);headers={}
 for line in lines[1:]:
  key,value=line.split(b':',1);headers.setdefault(key.lower(),[]).append(value.strip().lower())
 lengths=headers.get(b'content-length',[])
 if len(lengths)==1 and lengths[0].isdigit():return {'complete':len(entity)==int(lengths[0]),'entity_bytes':len(entity),'status':status,'framing':'content-length'}
 if headers.get(b'transfer-encoding')==[b'chunked']:return chunked_framing(entity,status)
 return {'complete':False,'entity_bytes':len(entity),'status':status,'framing':'close-or-unknown'}


def chunked_framing(entity,status):
 rest=entity;size=0
 while b'\r\n' in rest:
  line,tail=rest.split(b'\r\n',1)
  try:count=int(line.split(b';',1)[0],16)
  except ValueError:return {'complete':False,'entity_bytes':size,'status':status,'framing':'invalid-chunk'}
  if count==0:return {'complete':tail==b'\r\n','entity_bytes':size,'status':status,'framing':'chunked'}
  if len(tail)<count+2:break
  if tail[count:count+2]!=b'\r\n':break
  size+=count;rest=tail[count+2:]
 return {'complete':False,'entity_bytes':size,'status':status,'framing':'chunked'}


def received_entity_bytes(raw):
 if b'\r\n\r\n' not in raw:return 0
 head,remaining=raw.split(b'\r\n\r\n',1)
 header_lines=head.lower().split(b'\r\n')[1:]
 if not any(line.startswith(b'transfer-encoding:') for line in header_lines):return len(remaining)
 if b'transfer-encoding: chunked' not in header_lines:return 0
 count=0
 while b'\r\n' in remaining:
  line,tail=remaining.split(b'\r\n',1)
  try:size=int(line.split(b';',1)[0],16)
  except ValueError:return count
  if size<=0:return count
  count+=min(size,len(tail))
  if len(tail)<size+2 or tail[size:size+2]!=b'\r\n':return count
  remaining=tail[size+2:]
 return count


def socket_identity(connection):
 local=connection.getsockname();peer=connection.getpeername()
 state=os.fstat(connection.fileno())
 return {'local_address':local[0],'local_port':local[1],
  'peer_address':peer[0],'peer_port':peer[1],'fd':connection.fileno(),
  'socket_inode':state.st_ino,'socket_device':state.st_dev,'socket_mode':state.st_mode,**stamp()}


def same_live_socket(before,after):
 keys=('pid','fd','socket_inode','socket_device','local_address','local_port','peer_address','peer_port')
 return bool(before and after and before.get('socket_inode',0)>0 and all(before.get(key)==after.get(key) for key in keys))


def close_client_socket(connection,result,serial,reason):
 fd=connection.fileno();identity=socket_identity(connection) if fd>=0 else None
 connection.close()
 result.setdefault('connection_ends',[]).append({'connection_serial':serial,'reason':reason,
  'before_close':identity,'fd_after_close':connection.fileno(),**stamp()})


def valid_eagain_result(row,after_ns):
 return (row.get('requested_size_known') is True and isinstance(row.get('requested_bytes'),int) and row['requested_bytes']>0
  and isinstance(row.get('pid'),int) and row['pid']>0 and isinstance(row.get('socket_inode'),int) and row['socket_inode']>0
  and row.get('kernel_result')==-11 and row.get('errno')==11
  and row.get('fd_identity_unchanged') is True
  and isinstance(row.get('exit_monotonic_ns'),int) and after_ns<=row['exit_monotonic_ns']<=time.monotonic_ns())


def target_eagain(row,identity,nonce,after_ns):
 return (row.get('schema')=='traefik-own-child-syscall-v1' and row.get('nonce')==nonce
  and row.get('local_address')==identity['peer_address'] and row.get('local_port')==identity['peer_port']
  and row.get('peer_address')==identity['local_address'] and row.get('peer_port')==identity['local_port']
  and row.get('operation') in ('write','writev','sendto','sendmsg')
  and valid_eagain_result(row,after_ns))


def find_target_eagain(receipt,identity,nonce,started):
 for line in receipt.read_text().splitlines():
  try:row=json.loads(line)
  except json.JSONDecodeError:continue
  if target_eagain(row,identity,nonce,started):return row
 return None


def pause_for_eagain(root,options,identity,entity_bytes):
 # A missing physical event releases the reader on deadline and stays unqualified.
 # This receipt only controls reading; the packet consumer still joins the traced
 # PID/image/inode and subsequent successful write independently.
 seconds=options.get('deadline_seconds',10)
 if not isinstance(seconds,(int,float)) or not 0<seconds<=12:raise ValueError('invalid bounded EAGAIN pause')
 started=time.monotonic_ns();deadline=time.monotonic()+seconds;matched=None
 receipt=root/'host-syscalls.jsonl'
 while time.monotonic()<deadline:
  if receipt.exists():
   matched=find_target_eagain(receipt,identity,options['nonce'],started)
  if matched is not None:break
  time.sleep(0.01)
 result={'event':'client_read_pause','started_monotonic_ns':started,'released_monotonic_ns':time.monotonic_ns(),
  'entity_bytes_before_pause':entity_bytes,'socket':identity,'release_reason':'actual_target_eagain' if matched else 'deadline_without_target_eagain',
  'matched_syscall':matched,'unthrottled_after_release':True,'runtime_qualified':False}
 dump(root,'client-read-control.jsonl',result)
 return result


def entity_controls(connection,root,client_options,observe_primary,pause_options,pause,identity,entity_received,received):
 if not entity_received:return pause,None
 if observe_primary:(root/'client-first-entity').touch(exist_ok=True)
 if pause_options and pause is None and entity_received>=8192:
  pause=pause_for_eagain(root,pause_options,identity,entity_received)
 if client_options.get('kind')=='rst' and entity_received>=client_options.get('after_entity_bytes',8192):
  connection.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));connection.close();return pause,'client_SO_LINGER_RST'
 if client_options.get('kind')=='wait-for-sigterm' and entity_received>=8192:
  (root/'target-0.response.raw').write_bytes(received)
  progress={'pid':os.getpid(),'entity_bytes_received':entity_received,'raw_bytes':len(received),
   'raw_sha256':sha(received),'client_framing':framing(bytes(received)),**stamp()}
  (root/'client-signal-ready.json').write_text(json.dumps(progress,indent=2)+'\n')
  while True:signal.pause()
 return pause,None


def receive(connection,root,client_options,keepalive,observe_primary=True,socket_observation=None):
 received=bytearray();first=None;eof=False;reset=None;pause=None
 pause_options=client_options.get('pause_for_target_eagain') if observe_primary else None
 identity=(socket_observation or socket_identity(connection)) if pause_options else None
 while True:
  chunk,reset=receive_chunk(connection,pause_options,pause,received)
  if reset:break
  if not chunk:eof=True;break
  first=first or time.monotonic_ns();received.extend(chunk)
  retain_received(root,chunk,received,pause_options)
  pause,client_reset,complete=receive_controls(connection,root,client_options,observe_primary,pause_options,pause,identity,received,keepalive)
  if client_reset:reset=client_reset;break
  if complete:break
  slow_read_delay(client_options,pause_options)
 return bytes(received),{'first_recv_ns':first,'tcp_eof_observed':eof,'reset_observed':reset,'native_eos_inferred':False,'client_framing':framing(bytes(received)),'read_pause':pause}


def receive_chunk(connection,pause_options,pause,received):
 size=32768
 if pause_options and pause is None:size=min(size,max(1,8192-received_entity_bytes(bytes(received))))
 try:return connection.recv(size),None
 except ConnectionResetError as error:return None,type(error).__name__


def retain_received(root,chunk,received,pause_options):
 if pause_options:
  with (root/'target-0.response.partial.raw').open('ab') as stream:stream.write(chunk)
 if len(received)>MAX_RESPONSE_BYTES+65536:raise ValueError('bounded client response exceeded')


def slow_read_delay(client_options,pause_options):
 if client_options.get('slow_reader') and not pause_options:time.sleep(client_options.get('read_delay_seconds',0.01))


def client_label(readiness_index,positive,before,neighbor):
 if readiness_index is not None:return 'readiness-'+str(readiness_index)
 if positive:return 'positive'
 if before:return 'before-neighbor'
 if neighbor:return 'neighbor'
 return 'target'


def client_spec(spec,readiness_index,before_neighbor,positive_control):
 if readiness_index is not None:spec={**spec,'probe_id':spec['probe_id']+'-ready-'+str(readiness_index)}
 if before_neighbor:spec={**spec,'probe_id':spec['probe_id']+'-before'}
 if positive_control:
  control=spec['fixture']['sink_positive_control']
  spec={**spec,'probe_id':control['probe_id'],'fixture':{**spec['fixture'],
   'request':{**spec['fixture']['request'],'uri':control['uri']},'client':{'kind':'ordinary'}}}
 return spec


@dataclass
class ClientRequestContext:
 spec:dict
 root:Path
 result:dict
 neighbor:bool
 positive_control:bool
 before_neighbor:bool
 readiness_index:object
 options:dict
 sequence:list


def perform_request(context,connection,identity,serial,index,kind):
 spec=context.spec;root=context.root;result=context.result;neighbor=context.neighbor
 positive_control=context.positive_control;before_neighbor=context.before_neighbor
 readiness_index=context.readiness_index;options=context.options;sequence=context.sequence
 wire_probe=spec['probe_id']+'-seq-'+str(index) if not neighbor and len(sequence)>1 else spec['probe_id']
 request_spec={**spec,'probe_id':wire_probe}
 head,payload,lengths=raw_request(request_spec,neighbor,kind)
 label=client_label(readiness_index,positive_control,before_neighbor,neighbor)+'-'+str(index)
 before_send=socket_identity(connection)
 (root/(label+'.request.raw')).write_bytes(head+payload);connection.sendall(head)
 for chunk in segments(payload,lengths):connection.sendall(chunk);time.sleep(0.015)
 after_send=socket_identity(connection)
 raw,observation=receive(connection,root,options,bool(options.get('keepalive')),not neighbor and not positive_control,identity)
 after_receive=socket_identity(connection) if connection.fileno()>=0 else None
 (root/(label+'.response.raw')).write_bytes(raw)
 result['requests'].append(dict(observation,wire_probe=wire_probe+('-neighbor' if neighbor else ''),request_bytes=len(payload),request_sha256=sha(payload),raw_bytes=len(raw),raw_sha256=sha(raw),
  connection_serial=serial,socket_before_send=before_send,socket_after_send=after_send,socket_after_receive=after_receive,
  same_live_socket=same_live_socket(before_send,after_send) and same_live_socket(after_send,after_receive),**stamp()))


def client(spec,root,port,neighbor,before_neighbor=False,positive_control=False,readiness_index=None):
 spec=client_spec(spec,readiness_index,before_neighbor,positive_control)
 options={} if neighbor else spec['fixture'].get('client',{});sequence=['neighbor'] if neighbor else options.get('sequence',['target'])
 if not isinstance(sequence,list) or not 1<=len(sequence)<=3:raise ValueError('bounded original client sequence required')
 connection=None;serial=0;result={'probe':spec['probe_id'],'neighbor':neighbor,'requests':[],'connections':[],
  'connection_ends':[],'socket_receipt_schema':'same-live-client-socket-v1','observations_only':True,**stamp()}
 context=ClientRequestContext(spec,root,result,neighbor,positive_control,before_neighbor,readiness_index,options,sequence)
 try:
  for index,kind in enumerate(sequence):
   if connection is None:
    connection,identity=open_client(root,port,readiness_index,options,result,serial+1,spec,neighbor)
    serial+=1
   perform_request(context,connection,identity,serial,index,kind)
   if not options.get('keepalive') or connection.fileno()<0:
    close_client_socket(connection,result,serial,'response_complete_or_client_closed');connection=None
 except Exception as error:result['error']=type(error).__name__+': '+str(error)
 finally:
  if connection is not None:close_client_socket(connection,result,serial,'client_finally')
  output='client-'+client_label(readiness_index,positive_control,before_neighbor,neighbor)+'.json'
  result['completed_ns']=time.monotonic_ns();(root/output).write_text(json.dumps(result,indent=2)+'\n')
 return 0 if 'error' not in result else 1


def exact(connection,size):
 data=bytearray()
 while len(data)<size:
  chunk=connection.recv(size-len(data))
  if not chunk:return None
  data.extend(chunk)
 return bytes(data)
def companion_fault(client_socket,spec,root,opcode,length,bodies):
 kind=spec['fixture'].get('relay',{}).get('companion_fault')
 fault=kind=='delay-claim' and opcode==1 or kind=='delay-second-body' and opcode==3 and bodies>=2
 dump(root,PEER_LOG,dict(stamp(),event='received_frame',opcode=opcode,payload_bytes=length,synthetic_fault=kind))
 if fault:time.sleep(1.6)
 if kind=='peer-invalid-result':
  value=b'BAD!'+bytes(8);client_socket.sendall(value);dump(root,PEER_LOG,dict(stamp(),event='fault_write',hex=value.hex()));return True
 if kind=='peer-oversize':
  value=b'MRC1'+bytes([2,128,0,0])+int(65537).to_bytes(4,'big');client_socket.sendall(value);dump(root,PEER_LOG,dict(stamp(),event='fault_write',hex=value.hex()));return True
 return False


def companion_session(client_socket,spec,root,target):
 upstream=None
 try:
  upstream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);upstream.connect(target);upstream.settimeout(15);client_socket.settimeout(15);bodies=0
  while True:
   header=exact(client_socket,12)
   if header is None:break
   length=int.from_bytes(header[8:12],'big')
   if length>65536:raise ValueError('peer payload bound')
   payload=exact(client_socket,length)
   if payload is None:break
   opcode=header[5]
   if opcode==3:bodies+=1
   if companion_fault(client_socket,spec,root,opcode,length,bodies):break
   if not relay_companion_frame(client_socket,upstream,root,opcode,header,payload):break
 except Exception as error:dump(root,PEER_LOG,dict(stamp(),event='session_error',error=type(error).__name__))
 finally:
  client_socket.close()
  if upstream is not None:upstream.close()

def companion_proxy(spec,root,path,target):
 observer,native=companion_paths(root,path,target)
 server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(observer));os.chmod(observer,0o600);server.listen(16)
 try:
  while True:
   connection,_=server.accept();threading.Thread(target=companion_session,args=(connection,spec,root,str(native)),daemon=True).start()
 finally:server.close();observer.unlink(missing_ok=True)


def companion_paths(root,path,target):
 if (not root.is_absolute() or root.parent!=Path('/task/cases') or
     re.fullmatch(r'ac-[0-9a-f]{20}',root.name) is None or root.resolve(strict=True)!=root):
  raise ValueError('canonical admitted private case required')
 sockets=root/'sockets'
 if sockets.resolve(strict=True)!=sockets or not sockets.is_dir():raise ValueError('canonical socket directory required')
 state=sockets.stat()
 if state.st_uid!=os.geteuid() or state.st_mode&0o077:raise ValueError('private owned socket directory required')
 observer=sockets/'observer.sock';native=sockets/'companion.sock'
 if Path(path)!=observer or Path(target)!=native:raise ValueError('fixed companion socket pair required')
 if observer.is_symlink() or native.is_symlink():raise ValueError('socket symlink forbidden')
 return observer,native


def authorization_sample_path(root,label):
 filenames={'target':'auth-target.sample.raw','neighbor':'auth-neighbor.sample.raw',
  'positive':'auth-positive.sample.raw',
  'sequence-0':'auth-sequence-0.sample.raw','sequence-1':'auth-sequence-1.sample.raw','sequence-2':'auth-sequence-2.sample.raw',
  'readiness-0':'auth-readiness-0.sample.raw','readiness-1':'auth-readiness-1.sample.raw',
  'readiness-2':'auth-readiness-2.sample.raw','readiness-3':'auth-readiness-3.sample.raw',
  'readiness-4':'auth-readiness-4.sample.raw','readiness-5':'auth-readiness-5.sample.raw',
  'readiness-6':'auth-readiness-6.sample.raw','readiness-7':'auth-readiness-7.sample.raw',
  'readiness-8':'auth-readiness-8.sample.raw','readiness-9':'auth-readiness-9.sample.raw'}
 try:filename=filenames[label]
 except (KeyError,TypeError) as error:raise ValueError('fixed authorization sample label required') from error
 return root/filename


def validate_arguments(args,root):
 if root.parent!=Path('/task/cases') or args.root!=root or args.spec!=root/'case.json':raise ValueError('fixed admitted case root required')
 for port in (args.port,args.engine_port):
  if port is not None and not 1<=port<=65535:raise ValueError('bounded loopback port required')
 if args.socket is not None and Path(args.socket)!=root/'sockets/observer.sock':raise ValueError('fixed observer socket required')
 if args.target is not None and Path(args.target)!=root/'sockets/companion.sock':raise ValueError('fixed native socket required')
 if args.before_neighbor and not args.neighbor:raise ValueError('before-neighbor must be an independent neighbor')
 if args.positive_control and args.neighbor:raise ValueError('positive sink control is a separate target URI')
 validate_readiness_arguments(args)


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('backend','relay','client','companion-proxy'))
 parser.add_argument('--spec',type=Path,required=True);parser.add_argument('--root',type=Path,required=True)
 parser.add_argument('--port',type=int);parser.add_argument('--engine-port',type=int);parser.add_argument('--neighbor',action='store_true');parser.add_argument('--before-neighbor',action='store_true');parser.add_argument('--positive-control',action='store_true');parser.add_argument('--readiness-index',type=int);parser.add_argument('--socket');parser.add_argument('--target')
 args=parser.parse_args();root=args.root.resolve(strict=True)
 validate_arguments(args,root)
 spec=json.loads(args.spec.read_text())
 if args.mode=='client':return client(spec,root,args.port,args.neighbor,args.before_neighbor,args.positive_control,args.readiness_index)
 signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
 if args.mode=='companion-proxy':companion_proxy(spec,root,args.socket,args.target);return 0
 handler=Backend if args.mode=='backend' else Relay
 handler.spec=spec;handler.root=root;handler.engine_port=args.engine_port
 server=LoopbackEvidenceServer(args.port,handler)
 serve_private_http(server)
 return 0


def validate_backend_framing(lengths,encodings):
 if lengths and encodings:raise ValueError('backend CL+TE request is ambiguous')
 if len(lengths)>1 or len(encodings)>1:raise ValueError('duplicate backend request framing')


def add_transaction_header(spec,headers,probe):
 if not any(key.lower()=='x-request-id' for key,_ in headers):
  if spec['case_id']=='transaction_id_present':headers.append(['X-Request-Id','no-crs-tx-0001'])
  elif spec['case_id']!='transaction_id_generated_or_fallback':headers.append(['X-Request-Id',probe])


def receive_controls(connection,root,client_options,observe_primary,pause_options,pause,identity,received,keepalive):
 if b'\r\n\r\n' in received:
  entity_received=received_entity_bytes(bytes(received))
  pause,client_reset=entity_controls(connection,root,client_options,observe_primary,pause_options,pause,identity,entity_received,received)
  if client_reset:return pause,client_reset,False
  return pause,None,keepalive and framing(bytes(received))['complete']

 return pause,None,False


def open_client(root,port,readiness_index,options,result,serial,spec,neighbor):
 timeout=2 if readiness_index is not None else 15
 connection=client_connection(port,timeout);connection.settimeout(timeout)
 try:
  if options.get('receive_buffer'):connection.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,options['receive_buffer'])
  identity=socket_identity(connection);identity['connection_serial']=serial;identity['receive_buffer_bytes']=connection.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
  result['connections'].append(identity)
  dump(root,'client-connections.jsonl',dict(identity,probe=spec['probe_id'],neighbor=neighbor))
 except (OSError,ValueError,TypeError):
  connection.close();raise

 return connection,identity


def read_backend_length(length,maximum,receipt,exact):
 if not re.fullmatch(r'\d{1,10}',length,flags=re.ASCII):raise ValueError('invalid backend Content-Length')
 size=int(length)
 if size>maximum:raise ValueError('bounded backend body exceeded')
 receipt.update(framing='content-length',declared=size)
 exact(size,True);receipt['http_eos']=True


def relay_companion_frame(client_socket,upstream,root,opcode,header,payload):
 upstream.sendall(header+payload);response=exact(upstream,12)
 if response is None:return False
 size=int.from_bytes(response[8:12],'big')
 if size>65536:raise ValueError('peer result bound')
 data=exact(upstream,size)
 if data is None:return False
 client_socket.sendall(response+data);dump(root,PEER_LOG,dict(stamp(),event='relayed_result',opcode=opcode,result_bytes=size))

 return True


def validate_readiness_arguments(args):
 if args.readiness_index is not None and (args.mode!='client' or not args.neighbor or args.before_neighbor or args.positive_control or not 0<=args.readiness_index<10):raise ValueError('fixed independent readiness index required')


def backend_chunk(chunk,fixture,neighbor,written):
 if neighbor:return chunk
 truncate=fixture.get('truncate_after_bytes')
 if truncate is not None:return chunk[:max(0,truncate-written)]
 return chunk


def relay_header_value(key,value,mode,handle):
 if key.lower()!='x-msconnector-response-handle':return value
 if mode=='missing':return None
 if mode=='malformed':return 'i12-malformed'
 if mode=='unknown64hex':return '0'*64 if handle!='0'*64 else '1'*64
 return value

if __name__=='__main__':raise SystemExit(main())
