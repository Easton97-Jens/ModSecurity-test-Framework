/*
 * Test-only Apache handler for the Phase-4 terminal-output guard.
 *
 * It deliberately behaves like a broken output producer: after a Phase-4
 * deny has returned an error for its EOS brigade, it ignores that result and
 * attempts a distinct data/FLUSH/EOS brigade through r->output_filters.
 * Static (immortal) bucket payloads make the adversarial sequence valid for
 * both synchronous H1 and asynchronous H2 filter consumption.
 */

#include "httpd.h"
#include "ap_config.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"

#include <apr_buckets.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <string.h>


static apr_status_t phase4_rogue_append_immortal(request_rec *r,
    apr_bucket_brigade *brigade, const char *payload)
{
    apr_bucket *data = apr_bucket_immortal_create(payload, strlen(payload),
        r->connection->bucket_alloc);

    if (data == NULL)
    {
        return APR_ENOMEM;
    }
    APR_BRIGADE_INSERT_TAIL(brigade, data);
    return APR_SUCCESS;
}


static apr_status_t phase4_rogue_pass(request_rec *r, const char *payload,
    int flush, int eos, const char *suffix_after_eos)
{
    apr_bucket_brigade *brigade;
    apr_bucket *data;
    apr_status_t rc;

    brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (brigade == NULL)
    {
        return APR_ENOMEM;
    }
    rc = phase4_rogue_append_immortal(r, brigade, payload);
    if (rc != APR_SUCCESS)
    {
        apr_brigade_destroy(brigade);
        return rc;
    }
    if (flush)
    {
        data = apr_bucket_flush_create(r->connection->bucket_alloc);
        if (data == NULL)
        {
            apr_brigade_destroy(brigade);
            return APR_ENOMEM;
        }
        APR_BRIGADE_INSERT_TAIL(brigade, data);
    }
    if (eos)
    {
        data = apr_bucket_eos_create(r->connection->bucket_alloc);
        if (data == NULL)
        {
            apr_brigade_destroy(brigade);
            return APR_ENOMEM;
        }
        APR_BRIGADE_INSERT_TAIL(brigade, data);
    }
    if (suffix_after_eos != NULL)
    {
        rc = phase4_rogue_append_immortal(r, brigade, suffix_after_eos);
        if (rc != APR_SUCCESS)
        {
            apr_brigade_destroy(brigade);
            return rc;
        }
    }
    rc = ap_pass_brigade(r->output_filters, brigade);
    apr_brigade_cleanup(brigade);
    return rc;
}


#define PHASE4_FRAGMENTED_BUCKET_COUNT 4097U
#define PHASE4_FRAGMENTED_BUCKET_BOUNDARY_COUNT 4095U
#define PHASE4_FRAGMENTED_BUCKET_SPLIT_COUNT 2048U


static apr_status_t phase4_fragmented_bucket_pass(request_rec *r,
    unsigned int bucket_count)
{
    static const char payload[] = "f";
    apr_bucket_brigade *brigade;
    apr_bucket *bucket;
    apr_status_t rc;

    brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (brigade == NULL)
    {
        return APR_ENOMEM;
    }
    /* The first pass deliberately has no EOS.  The second pass provides the
     * remaining data and EOS, exercising the persistent counter across
     * separate Apache output-filter invocations. */
    for (unsigned int index = 0U; index < bucket_count; ++index)
    {
        bucket = apr_bucket_immortal_create(payload, 1U,
            r->connection->bucket_alloc);
        if (bucket == NULL)
        {
            apr_brigade_destroy(brigade);
            return APR_ENOMEM;
        }
        APR_BRIGADE_INSERT_TAIL(brigade, bucket);
        if (index + 1U == PHASE4_FRAGMENTED_BUCKET_SPLIT_COUNT &&
            index + 1U < bucket_count)
        {
            rc = ap_pass_brigade(r->output_filters, brigade);
            apr_brigade_cleanup(brigade);
            if (rc != APR_SUCCESS)
            {
                return rc;
            }
            brigade = apr_brigade_create(r->pool,
                r->connection->bucket_alloc);
            if (brigade == NULL)
            {
                return APR_ENOMEM;
            }
        }
    }
    bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        apr_brigade_destroy(brigade);
        return APR_ENOMEM;
    }
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
    rc = ap_pass_brigade(r->output_filters, brigade);
    apr_brigade_cleanup(brigade);
    return rc;
}


static apr_status_t phase4_downstream_error_filter(ap_filter_t *f,
    apr_bucket_brigade *bb_in)
{
    apr_bucket_brigade *brigade;
    apr_bucket *bucket;
    apr_status_t rc;

    if (f == NULL || f->r == NULL || f->r->connection == NULL ||
        f->next == NULL)
    {
        if (bb_in != NULL)
        {
            apr_brigade_cleanup(bb_in);
        }
        return APR_EGENERAL;
    }
    /* This filter is registered immediately downstream of MODSECURITY_OUT.
     * It receives the fully released, P4-allowed brigade, discards it before
     * HTTP_HEADER sees any byte, and creates a new first error bucket from
     * this filter. That satisfies Apache's error-bucket contract and drives a
     * real downstream ap_die()/ErrorDocument transition. */
    if (bb_in != NULL)
    {
        apr_brigade_cleanup(bb_in);
    }
    brigade = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
    if (brigade == NULL)
    {
        return APR_ENOMEM;
    }
    bucket = ap_bucket_error_create(HTTP_INTERNAL_SERVER_ERROR, NULL,
        f->r->pool, f->r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        apr_brigade_destroy(brigade);
        return APR_ENOMEM;
    }
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
    bucket = apr_bucket_eos_create(f->r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        apr_brigade_destroy(brigade);
        return APR_ENOMEM;
    }
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, f->r,
        "ModSecurity Phase4 downstream error test replaced the released response with an error bucket");
    rc = ap_pass_brigade(f->next, brigade);
    apr_brigade_cleanup(brigade);
    return rc;
}


static apr_status_t phase4_upstream_error_pass(request_rec *r)
{
    apr_bucket_brigade *brigade;
    apr_bucket *bucket;
    apr_status_t rc;

    brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (brigade == NULL)
    {
        return APR_ENOMEM;
    }
    /* This is a valid Apache error brigade: the error bucket is its first
     * bucket and this handler has not emitted any earlier brigade. It enters
     * MODSECURITY_OUT before setaside, exercising the connector's special
     * first-error path without exposing an original response byte. */
    bucket = ap_bucket_error_create(HTTP_INTERNAL_SERVER_ERROR, NULL,
        r->pool, r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        apr_brigade_destroy(brigade);
        return APR_ENOMEM;
    }
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
    bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        apr_brigade_destroy(brigade);
        return APR_ENOMEM;
    }
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
    rc = ap_pass_brigade(r->output_filters, brigade);
    apr_brigade_cleanup(brigade);
    return rc;
}


static int phase4_terminal_rogue_handler(request_rec *r)
{
    apr_status_t first_rc;
    apr_status_t deny_rc;
    apr_status_t late_rc;
    char *phase3_etag = NULL;
    int header_mutation = 0;

    if (r->handler == NULL ||
        strcmp(r->handler, "phase4-terminal-rogue") != 0)
    {
        return DECLINED;
    }

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/plain");
    apr_table_setn(r->headers_out, "X-Phase4-Original-Response", "rogue");
    if (r->uri != NULL &&
        strcmp(r->uri, "/__phase4_rogue_header") == 0)
    {
        phase3_etag = apr_pstrdup(r->pool, "\"phase3-inspected-etag\"");
        if (phase3_etag == NULL)
        {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        /* Dynamic handlers may inherit Apache's no-etag note before their
         * first output callback.  Clear that pre-existing suppression before
         * Phase 3 so the deliberately supplied ETag is both inspected and
         * included in the response-state snapshot. */
        apr_table_unset(r->notes, "no-etag");
        apr_table_setn(r->headers_out, "ETag", phase3_etag);
    }

    first_rc = phase4_rogue_pass(r, "phase4-rogue-prefix-", 1, 0, NULL);
    /* This route changes response state after the first output callback.
     * Without the connector's Phase-3 snapshot/restore, holding the brigade
     * to EOS would replace the Phase-3-inspected ETag, add an uninspected
     * header, and activate no-etag before Apache serializes the response.
     * The test therefore requires the original ETag and the absence of the
     * late header in the visible response. */
    if (r->uri != NULL &&
        strcmp(r->uri, "/__phase4_rogue_header") == 0)
    {
        if (phase3_etag == NULL)
        {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_table_setn(r->headers_out, "X-Phase3-Late", "blocked");
        apr_table_setn(r->notes, "no-etag", "1");
        phase3_etag[1] = 'X';
        r->header_only = 1;
        header_mutation = 1;
    }
    deny_rc = phase4_rogue_pass(r, "no-crs-response-body-marker", 0, 1,
        "phase4-rogue-suffix-after-eos");

    /* Intentionally ignore deny_rc. This is the post-error/reset-chain
     * adversary the connector must contain without leaking a second body or
     * terminal metadata sequence. */
    late_rc = phase4_rogue_pass(r, "phase4-rogue-late-after-deny", 1, 1,
        NULL);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 rogue test issued late response brigade "
        "first_rc=%d deny_rc=%d late_rc=%d header_mutation=%d",
        (int)first_rc, (int)deny_rc, (int)late_rc, header_mutation);
    return OK;
}


static int phase4_fragmented_bucket_handler(request_rec *r)
{
    apr_status_t rc;
    unsigned int bucket_count;

    if (r->handler == NULL ||
        (strcmp(r->handler, "phase4-fragmented-bucket") != 0 &&
         strcmp(r->handler, "phase4-fragmented-bucket-boundary") != 0))
    {
        return DECLINED;
    }

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/plain");
    bucket_count = strcmp(r->handler,
        "phase4-fragmented-bucket-boundary") == 0
        ? PHASE4_FRAGMENTED_BUCKET_BOUNDARY_COUNT
        : PHASE4_FRAGMENTED_BUCKET_COUNT;
    rc = phase4_fragmented_bucket_pass(r, bucket_count);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 fragmented-bucket test emitted %u one-byte buckets in two brigades rc=%d",
        bucket_count, (int)rc);
    /* The connector owns the terminal error path when it rejects the
     * withheld brigade. Returning OK avoids creating a second Apache error
     * sequence after that fail-closed decision. */
    return OK;
}


static int phase4_internal_redirect_handler(request_rec *r)
{
    const char *target_uri;

    if (r->handler == NULL ||
        (strcmp(r->handler, "phase4-internal-redirect") != 0 &&
         strcmp(r->handler,
             "phase4-internal-redirect-target-handler-test") != 0))
    {
        return DECLINED;
    }

    /* Exercise Apache's normal internal redirect machinery before any
     * response brigade is emitted by this request. The marker-target route
     * is deliberately a handler rather than a static file: the harness must
     * prove that the connector rejects the redirect before Apache invokes an
     * arbitrary target handler with potential side effects. */
    target_uri = "/__phase4_internal_redirect_target.txt";
    if (strcmp(r->handler,
            "phase4-internal-redirect-target-handler-test") == 0)
    {
        target_uri = "/__phase4_internal_redirect_target_handler_target";
    }
    ap_internal_redirect(target_uri, r);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 redirect test issued an internal redirect");
    return OK;
}


static int phase4_internal_redirect_target_handler(request_rec *r)
{
    if (r->handler == NULL ||
        strcmp(r->handler,
            "phase4-internal-redirect-target-handler-marker") != 0)
    {
        return DECLINED;
    }

    /* This marker is intentionally emitted before any response brigade. A
     * normal P4 redirect must be rejected before this handler can run. */
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 redirect target handler executed");
    return OK;
}


static int phase4_nested_error_document_redirect_handler(request_rec *r)
{
    if (r->handler == NULL ||
        strcmp(r->handler, "phase4-nested-error-document-redirect") != 0)
    {
        return DECLINED;
    }

    /* This runs only after Apache has accepted the one local ErrorDocument
     * redirect for a P4 deny. A second redirect must be refused rather than
     * turning that bounded exception into a new producer response. */
    ap_internal_redirect("/__phase4_internal_redirect_target.txt", r);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 nested ErrorDocument test issued a second internal redirect");
    return OK;
}


static int phase4_preoutput_error_document_handler(request_rec *r)
{
    if (r->handler == NULL ||
        strcmp(r->handler, "phase4-preoutput-error-document") != 0)
    {
        return DECLINED;
    }

    /* Return an ordinary Apache error before emitting a body brigade. The
     * connector intentionally refuses its local ErrorDocument redirect: its
     * target may have a different per-directory Policy/RulesSet, which cannot
     * be safely rebound through the libModSecurity C API. */
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 preoutput ErrorDocument test returned HTTP_NOT_FOUND before any response brigade");
    return HTTP_NOT_FOUND;
}


static int phase4_downstream_error_handler(request_rec *r)
{
    apr_status_t rc;

    if (r->handler == NULL ||
        strcmp(r->handler, "phase4-downstream-error") != 0)
    {
        return DECLINED;
    }

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/plain");
    apr_table_setn(r->headers_out, "X-Phase4-Original-Response", "downstream");
    if (ap_add_output_filter("PHASE4_DOWNSTREAM_ERROR", NULL, r,
            r->connection) == NULL)
    {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = phase4_rogue_pass(r, "no-crs-response-body-marker", 0, 1, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 downstream error test released an allowed brigade rc=%d",
        (int)rc);
    return OK;
}


static int phase4_upstream_error_handler(request_rec *r)
{
    apr_status_t rc;

    if (r->handler == NULL ||
        strcmp(r->handler, "phase4-upstream-error") != 0)
    {
        return DECLINED;
    }

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/plain");
    apr_table_setn(r->headers_out, "X-Phase4-Original-Response", "upstream");
    rc = phase4_upstream_error_pass(r);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r,
        "ModSecurity Phase4 upstream error test issued a first error bucket rc=%d",
        (int)rc);
    return OK;
}


static void phase4_terminal_rogue_register_hooks(apr_pool_t *pool)
{
    (void)pool;
    ap_hook_handler(phase4_terminal_rogue_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(phase4_fragmented_bucket_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(phase4_internal_redirect_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(&phase4_internal_redirect_target_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(phase4_nested_error_document_redirect_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(&phase4_preoutput_error_document_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(phase4_downstream_error_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_hook_handler(phase4_upstream_error_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
    ap_register_output_filter("PHASE4_DOWNSTREAM_ERROR",
        phase4_downstream_error_filter, NULL, AP_FTYPE_CONTENT_SET - 2);
}


module AP_MODULE_DECLARE_DATA phase4_terminal_rogue_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &phase4_terminal_rogue_register_hooks,
    AP_MODULE_FLAG_NONE
};
