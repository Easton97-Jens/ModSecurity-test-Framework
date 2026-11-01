/*
 * Exercises the production Apache transaction cleanup callback against real
 * APR pool ordering.  The native cleanup symbol is deliberately replaced by
 * a counter so the test can assert ownership and call order without a live
 * libmodsecurity engine.
 */

#include <assert.h>
#include <stdio.h>

#include "mod_security3.h"
#include "msc_utils.h"


typedef struct
{
    int marker;
} fake_transaction;


static unsigned int native_cleanup_calls;
static Transaction *native_cleanup_seen[8];
static msc_t *expected_msr;
static request_rec *expected_owner;
module AP_MODULE_DECLARE_DATA security3_module = { .module_index = 0 };


void msc_transaction_cleanup(Transaction *transaction)
{
    assert(transaction != NULL);
    assert(native_cleanup_calls < (sizeof(native_cleanup_seen) /
        sizeof(native_cleanup_seen[0])));
    assert(expected_msr != NULL);
    assert(expected_owner != NULL);
    assert(expected_msr->t == NULL);
    assert(expected_msr->owner_request == NULL);
    assert(ap_get_module_config(expected_owner->request_config,
        &security3_module) == NULL);

    native_cleanup_seen[native_cleanup_calls] = transaction;
    native_cleanup_calls++;
}


static void reset_observations(void)
{

    native_cleanup_calls = 0U;
    expected_msr = NULL;
    expected_owner = NULL;
    for (unsigned int index = 0U;
        index < (sizeof(native_cleanup_seen) / sizeof(native_cleanup_seen[0]));
        index++)
    {
        native_cleanup_seen[index] = NULL;
    }
}


static void expect_cleanup(msc_t *msr, request_rec *owner)
{
    expected_msr = msr;
    expected_owner = owner;
}


static msc_t *create_request_context(apr_pool_t *pool,
    request_rec **owner_out, Transaction *transaction)
{
    request_rec *owner;
    msc_t *msr;

    owner = apr_pcalloc(pool, sizeof(*owner));
    msr = apr_pcalloc(pool, sizeof(*msr));
    assert(owner != NULL);
    assert(msr != NULL);

    owner->pool = pool;
    owner->notes = apr_table_make(pool, 1);
    assert(owner->notes != NULL);
    msr->r = owner;
    msr->owner_request = owner;
    msr->t = transaction;
    owner->request_config = apr_pcalloc(pool, sizeof(void *));
    assert(owner->request_config != NULL);
    ap_set_module_config(owner->request_config, &security3_module, msr);
    apr_pool_cleanup_register(pool, msr, msc_cleanup_request_transaction,
        apr_pool_cleanup_null);

    *owner_out = owner;
    return msr;
}


static void test_normal_request_cleanup(void)
{
    apr_pool_t *pool;
    request_rec *owner;
    fake_transaction native = { 1 };
    msc_t *msr;

    reset_observations();
    assert(apr_pool_create(&pool, NULL) == APR_SUCCESS);
    msr = create_request_context(pool, &owner, (Transaction *)(void *)&native);
    expect_cleanup(msr, owner);
    apr_pool_destroy(pool);

    assert(native_cleanup_calls == 1U);
    assert(native_cleanup_seen[0] == (Transaction *)(void *)&native);
}


static void test_keepalive_request_pools_are_independent(void)
{
    apr_pool_t *connection_pool;
    apr_pool_t *first_request_pool;
    apr_pool_t *second_request_pool;
    request_rec *first_owner;
    request_rec *second_owner;
    fake_transaction first_native = { 1 };
    fake_transaction second_native = { 2 };
    msc_t *first_msr;
    msc_t *second_msr;

    reset_observations();
    assert(apr_pool_create(&connection_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&first_request_pool, connection_pool) == APR_SUCCESS);
    assert(apr_pool_create(&second_request_pool, connection_pool) == APR_SUCCESS);
    first_msr = create_request_context(first_request_pool, &first_owner,
        (Transaction *)(void *)&first_native);
    second_msr = create_request_context(second_request_pool, &second_owner,
        (Transaction *)(void *)&second_native);

    expect_cleanup(first_msr, first_owner);
    apr_pool_destroy(first_request_pool);
    assert(native_cleanup_calls == 1U);
    assert(native_cleanup_seen[0] == (Transaction *)(void *)&first_native);
    assert(second_msr->t == (Transaction *)(void *)&second_native);
    assert(ap_get_module_config(second_owner->request_config,
        &security3_module) == second_msr);

    expect_cleanup(second_msr, second_owner);
    apr_pool_destroy(second_request_pool);
    assert(native_cleanup_calls == 2U);
    assert(native_cleanup_seen[1] == (Transaction *)(void *)&second_native);
    apr_pool_destroy(connection_pool);
}


static void test_failed_creation_has_no_cleanup(void)
{
    apr_pool_t *pool;
    const msc_t *msr;

    reset_observations();
    assert(apr_pool_create(&pool, NULL) == APR_SUCCESS);
    msr = apr_pcalloc(pool, sizeof(*msr));
    assert(msr != NULL);
    assert(msr->t == NULL);
    apr_pool_destroy(pool);

    assert(native_cleanup_calls == 0U);
}


static void test_early_error_and_intervention_cleanup(void)
{
    apr_pool_t *error_pool;
    apr_pool_t *intervention_pool;
    request_rec *error_owner;
    request_rec *intervention_owner;
    fake_transaction error_native = { 1 };
    fake_transaction intervention_native = { 2 };
    msc_t *error_msr;
    msc_t *intervention_msr;

    reset_observations();
    assert(apr_pool_create(&error_pool, NULL) == APR_SUCCESS);
    error_msr = create_request_context(error_pool, &error_owner,
        (Transaction *)(void *)&error_native);
    expect_cleanup(error_msr, error_owner);
    apr_pool_destroy(error_pool);
    assert(native_cleanup_calls == 1U);

    assert(apr_pool_create(&intervention_pool, NULL) == APR_SUCCESS);
    intervention_msr = create_request_context(intervention_pool,
        &intervention_owner, (Transaction *)(void *)&intervention_native);
    expect_cleanup(intervention_msr, intervention_owner);
    apr_pool_destroy(intervention_pool);
    assert(native_cleanup_calls == 2U);
}


static void test_abort_and_duplicate_cleanup_are_safe(void)
{
    apr_pool_t *pool;
    request_rec *owner;
    fake_transaction native = { 1 };
    msc_t *msr;

    reset_observations();
    assert(apr_pool_create(&pool, NULL) == APR_SUCCESS);
    msr = create_request_context(pool, &owner, (Transaction *)(void *)&native);
    expect_cleanup(msr, owner);
    assert(msc_cleanup_request_transaction(msr) == APR_SUCCESS);
    assert(native_cleanup_calls == 1U);
    assert(msr->t == NULL);
    assert(msr->owner_request == NULL);
    assert(ap_get_module_config(owner->request_config,
        &security3_module) == NULL);

    apr_pool_destroy(pool);
    assert(native_cleanup_calls == 1U);
}


static void test_subrequest_and_redirect_preserve_owner_cleanup(void)
{
    apr_pool_t *owner_pool;
    apr_pool_t *subrequest_pool;
    request_rec *owner;
    request_rec *subrequest;
    request_rec *redirect;
    fake_transaction native = { 1 };
    msc_t *msr;

    reset_observations();
    assert(apr_pool_create(&owner_pool, NULL) == APR_SUCCESS);
    msr = create_request_context(owner_pool, &owner,
        (Transaction *)(void *)&native);
    assert(apr_pool_create(&subrequest_pool, owner_pool) == APR_SUCCESS);
    subrequest = apr_pcalloc(subrequest_pool, sizeof(*subrequest));
    assert(subrequest != NULL);
    subrequest->pool = subrequest_pool;
    msr->r = subrequest;
    apr_pool_destroy(subrequest_pool);
    assert(native_cleanup_calls == 0U);
    assert(msr->t == (Transaction *)(void *)&native);

    redirect = apr_pcalloc(owner_pool, sizeof(*redirect));
    assert(redirect != NULL);
    redirect->pool = owner_pool;
    msr->r = redirect;
    expect_cleanup(msr, owner);
    apr_pool_destroy(owner_pool);
    assert(native_cleanup_calls == 1U);
    assert(native_cleanup_seen[0] == (Transaction *)(void *)&native);
}


int main(void)
{
    assert(apr_initialize() == APR_SUCCESS);

    test_normal_request_cleanup();
    test_keepalive_request_pools_are_independent();
    test_failed_creation_has_no_cleanup();
    test_early_error_and_intervention_cleanup();
    test_abort_and_duplicate_cleanup_are_safe();
    test_subrequest_and_redirect_preserve_owner_cleanup();

    apr_terminate();
    puts("PASS: Apache request transaction cleanup APR lifecycle harness");
    return 0;
}
