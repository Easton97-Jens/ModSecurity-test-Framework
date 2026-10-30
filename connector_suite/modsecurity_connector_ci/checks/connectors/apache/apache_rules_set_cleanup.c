/*
 * Exercise Apache directory-configuration RulesSet cleanup against real APR
 * pool lifecycles. The native RulesSet API and common-config merge are
 * deterministic in-process stubs, so the test isolates connector ownership
 * without requiring a live ModSecurity engine.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mod_security3.h"


enum
{
    MAX_FAKE_RULES_SETS = 16
};


typedef struct
{
    unsigned int cleanup_calls;
} fake_rules_set;


static fake_rules_set fake_rules_sets[MAX_FAKE_RULES_SETS];
static unsigned int create_attempts;
static unsigned int created_rules_sets;
static unsigned int native_cleanup_calls;
static unsigned int rules_merge_calls;
static unsigned int rules_merge_fail_on_call;
static unsigned int config_merge_calls;
static unsigned int config_validate_calls;
static int next_create_returns_null;
static int config_merge_returns_failure;


void *msc_hook_create_config_directory(apr_pool_t *mp, char *path);
void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child);


static fake_rules_set *fake_rules_set_from_native(const RulesSet *rules)
{

    assert(rules != NULL);
    for (unsigned int index = 0U; index < created_rules_sets; index++)
    {
        if (rules == (RulesSet *)(void *)&fake_rules_sets[index])
        {
            return &fake_rules_sets[index];
        }
    }

    assert(!"unexpected RulesSet passed to lifecycle stub");
    return NULL;
}


static void reset_observations(void)
{
    memset(fake_rules_sets, 0, sizeof(fake_rules_sets));
    create_attempts = 0U;
    created_rules_sets = 0U;
    native_cleanup_calls = 0U;
    rules_merge_calls = 0U;
    rules_merge_fail_on_call = 0U;
    config_merge_calls = 0U;
    config_validate_calls = 0U;
    next_create_returns_null = 0;
    config_merge_returns_failure = 0;
}


RulesSet *msc_create_rules_set(void)
{
    fake_rules_set *rules;

    create_attempts++;
    if (next_create_returns_null != 0)
    {
        next_create_returns_null = 0;
        return NULL;
    }

    assert(created_rules_sets < MAX_FAKE_RULES_SETS);
    rules = &fake_rules_sets[created_rules_sets];
    created_rules_sets++;
    return (RulesSet *)(void *)rules;
}


int msc_rules_cleanup(RulesSet *rules)
{
    fake_rules_set *fake = fake_rules_set_from_native(rules);

    assert(fake->cleanup_calls == 0U);
    fake->cleanup_calls++;
    native_cleanup_calls++;
    return 0;
}


int msc_rules_merge(RulesSet *rules_dst, RulesSet *rules_from,
    const char **error)
{
    assert(rules_dst != NULL);
    assert(rules_from != NULL);
    rules_merge_calls++;
    if (rules_merge_fail_on_call == rules_merge_calls)
    {
        if (error != NULL)
        {
            *error = "forced RulesSet merge failure";
        }
        return -1;
    }
    return 0;
}


void msconnector_config_init(msconnector_config *config)
{
    assert(config != NULL);
    memset(config, 0, sizeof(*config));
}


int msconnector_config_merge(msconnector_config *out,
    const msconnector_config *parent, const msconnector_config *child)
{
    assert(out != NULL);
    config_merge_calls++;
    if (config_merge_returns_failure != 0)
    {
        return 0;
    }

    if (child != NULL)
    {
        *out = *child;
    }
    else if (parent != NULL)
    {
        *out = *parent;
    }
    else
    {
        msconnector_config_init(out);
    }
    return 1;
}


int msconnector_config_validate(const msconnector_config *config, char *error,
    size_t error_len)
{
    assert(config != NULL);
    config_validate_calls++;
    if (error != NULL && error_len > 0U)
    {
        error[0] = '\0';
    }
    return 1;
}


/* Error logging is outside this lifecycle contract. GNU ld redirects all
 * production log calls to this fixed-signature no-op through --wrap. */
void __wrap_ap_log_perror_(void)
{
    /* The harness asserts lifecycle ownership, not Apache log output. */
}


static msc_conf_t *create_config(apr_pool_t *pool)
{
    msc_conf_t *config = (msc_conf_t *)msc_hook_create_config_directory(pool,
        NULL);

    assert(config != NULL);
    assert(config->rules_set != NULL);
    return config;
}


static void test_non_null_configs_clean_once_per_pool(void)
{
    apr_pool_t *first_pool;
    apr_pool_t *second_pool;
    const msc_conf_t *first;
    const msc_conf_t *second;

    reset_observations();
    assert(apr_pool_create(&first_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&second_pool, NULL) == APR_SUCCESS);
    first = create_config(first_pool);
    second = create_config(second_pool);
    assert(first->rules_set != second->rules_set);
    assert(create_attempts == 2U);
    assert(created_rules_sets == 2U);

    apr_pool_destroy(first_pool);
    assert(native_cleanup_calls == 1U);
    assert(fake_rules_sets[0].cleanup_calls == 1U);
    assert(fake_rules_sets[1].cleanup_calls == 0U);

    apr_pool_destroy(second_pool);
    assert(native_cleanup_calls == 2U);
    assert(fake_rules_sets[1].cleanup_calls == 1U);
}


static void test_null_rules_set_never_registers_cleanup(void)
{
    apr_pool_t *pool;

    reset_observations();
    next_create_returns_null = 1;
    assert(apr_pool_create(&pool, NULL) == APR_SUCCESS);
    assert(msc_hook_create_config_directory(pool, NULL) == NULL);
    assert(create_attempts == 1U);
    assert(created_rules_sets == 0U);
    apr_pool_destroy(pool);
    assert(native_cleanup_calls == 0U);
}


static void test_pool_clear_does_not_repeat_rules_set_cleanup(void)
{
    apr_pool_t *pool;

    reset_observations();
    assert(apr_pool_create(&pool, NULL) == APR_SUCCESS);
    (void)create_config(pool);
    apr_pool_clear(pool);
    assert(native_cleanup_calls == 1U);
    assert(fake_rules_sets[0].cleanup_calls == 1U);
    apr_pool_destroy(pool);
    assert(native_cleanup_calls == 1U);
}


static void test_successful_merge_has_its_own_pool_owned_rules_set(void)
{
    apr_pool_t *parent_pool;
    apr_pool_t *child_pool;
    apr_pool_t *merged_pool;
    msc_conf_t *parent;
    msc_conf_t *child;
    const msc_conf_t *merged;

    reset_observations();
    assert(apr_pool_create(&parent_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&child_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&merged_pool, NULL) == APR_SUCCESS);
    parent = create_config(parent_pool);
    child = create_config(child_pool);
    merged = (msc_conf_t *)msc_hook_merge_config_directory(merged_pool, parent,
        child);
    assert(merged != NULL);
    assert(merged->rules_set != parent->rules_set);
    assert(merged->rules_set != child->rules_set);
    assert(created_rules_sets == 3U);
    assert(rules_merge_calls == 2U);
    assert(config_merge_calls == 1U);

    apr_pool_destroy(merged_pool);
    assert(native_cleanup_calls == 1U);
    apr_pool_destroy(parent_pool);
    assert(native_cleanup_calls == 2U);
    apr_pool_destroy(child_pool);
    assert(native_cleanup_calls == 3U);
}


static void test_rules_merge_error_keeps_new_rules_set_pool_owned(void)
{
    apr_pool_t *parent_pool;
    apr_pool_t *child_pool;
    apr_pool_t *merged_pool;
    msc_conf_t *parent;
    msc_conf_t *child;

    reset_observations();
    rules_merge_fail_on_call = 1U;
    assert(apr_pool_create(&parent_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&child_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&merged_pool, NULL) == APR_SUCCESS);
    parent = create_config(parent_pool);
    child = create_config(child_pool);
    assert(msc_hook_merge_config_directory(merged_pool, parent, child) == NULL);
    assert(created_rules_sets == 3U);
    assert(rules_merge_calls == 1U);

    apr_pool_destroy(merged_pool);
    assert(native_cleanup_calls == 1U);
    apr_pool_destroy(parent_pool);
    assert(native_cleanup_calls == 2U);
    apr_pool_destroy(child_pool);
    assert(native_cleanup_calls == 3U);
}


static void test_second_rules_merge_error_keeps_new_rules_set_pool_owned(void)
{
    apr_pool_t *parent_pool;
    apr_pool_t *child_pool;
    apr_pool_t *merged_pool;
    msc_conf_t *parent;
    msc_conf_t *child;

    reset_observations();
    rules_merge_fail_on_call = 2U;
    assert(apr_pool_create(&parent_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&child_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&merged_pool, NULL) == APR_SUCCESS);
    parent = create_config(parent_pool);
    child = create_config(child_pool);
    assert(msc_hook_merge_config_directory(merged_pool, parent, child) == NULL);
    assert(created_rules_sets == 3U);
    assert(rules_merge_calls == 2U);

    apr_pool_destroy(merged_pool);
    assert(native_cleanup_calls == 1U);
    apr_pool_destroy(parent_pool);
    assert(native_cleanup_calls == 2U);
    apr_pool_destroy(child_pool);
    assert(native_cleanup_calls == 3U);
}


static void test_common_config_error_keeps_new_rules_set_pool_owned(void)
{
    apr_pool_t *parent_pool;
    apr_pool_t *child_pool;
    apr_pool_t *merged_pool;
    msc_conf_t *parent;
    msc_conf_t *child;

    reset_observations();
    config_merge_returns_failure = 1;
    assert(apr_pool_create(&parent_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&child_pool, NULL) == APR_SUCCESS);
    assert(apr_pool_create(&merged_pool, NULL) == APR_SUCCESS);
    parent = create_config(parent_pool);
    child = create_config(child_pool);
    assert(msc_hook_merge_config_directory(merged_pool, parent, child) == NULL);
    assert(created_rules_sets == 3U);
    assert(rules_merge_calls == 2U);
    assert(config_merge_calls == 1U);
    assert(config_validate_calls == 1U);

    apr_pool_destroy(merged_pool);
    assert(native_cleanup_calls == 1U);
    apr_pool_destroy(parent_pool);
    assert(native_cleanup_calls == 2U);
    apr_pool_destroy(child_pool);
    assert(native_cleanup_calls == 3U);
}


int main(void)
{
    assert(apr_initialize() == APR_SUCCESS);

    test_non_null_configs_clean_once_per_pool();
    test_null_rules_set_never_registers_cleanup();
    test_pool_clear_does_not_repeat_rules_set_cleanup();
    test_successful_merge_has_its_own_pool_owned_rules_set();
    test_rules_merge_error_keeps_new_rules_set_pool_owned();
    test_second_rules_merge_error_keeps_new_rules_set_pool_owned();
    test_common_config_error_keeps_new_rules_set_pool_owned();

    apr_terminate();
    puts("PASS: Apache RulesSet cleanup APR lifecycle harness");
    return 0;
}
