/*
  +----------------------------------------------------------------------+
  | ext/test_helper                                                      |
  | An extension for the PHP Interpreter to ease testing of PHP code.    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2011 Sebastian Bergmann. All rights reserved.          |
  +----------------------------------------------------------------------+
  | Redistribution and use in source and binary forms, with or without   |
  | modification, are permitted provided that the following conditions   |
  | are met:                                                             |
  |                                                                      |
  |  * Redistributions of source code must retain the above copyright    |
  |    notice, this list of conditions and the following disclaimer.     |
  |                                                                      |
  |  * Redistributions in binary form must reproduce the above copyright |
  |    notice, this list of conditions and the following disclaimer in   |
  |    the documentation and/or other materials provided with the        |
  |    distribution.                                                     |
  |                                                                      |
  |  * Neither the name of Sebastian Bergmann nor the names of his       |
  |    contributors may be used to endorse or promote products derived   |
  |    from this software without specific prior written permission.     |
  |                                                                      |
  | THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS  |
  | "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT    |
  | LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS    |
  | FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE       |
  | COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,  |
  | INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, |
  | BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;     |
  | LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER     |
  | CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT   |
  | LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN    |
  | ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE      |
  | POSSIBILITY OF SUCH DAMAGE.                                          |
  +----------------------------------------------------------------------+
  | Author: Johannes Schlüter <johannes@schlueters.de>                   |
  |         Scott MacVicar <scott@macvicar.net>                          |
  |         Sebastian Bergmann <sb@sebastian-bergmann.de>                |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_test_helpers.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_extensions.h"

#ifdef PHP_WIN32
#   define PHP_TEST_HELPERS_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_TEST_HELPERS_API __attribute__ ((visibility("default")))
#else
#   define PHP_TEST_HELPERS_API
#endif

#if PHP_VERSION_ID < 50300
typedef opcode_handler_t user_opcode_handler_t;

#define Z_ADDREF_P(z) ((z)->refcount++)


#define zend_parse_parameters_none() zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "")

static void zend_fcall_info_args_clear(zend_fcall_info *fci, int free_mem) /* {{{ */
{
    if (fci->params) {
        if (free_mem) {
            efree(fci->params);
            fci->params = NULL;
        }
    }
    fci->param_count = 0;
}
/* }}} */

static int zend_fcall_info_argv(zend_fcall_info *fci TSRMLS_DC, int argc, va_list *argv) /* {{{ */
{
    int i;
    zval **arg;

    if (argc < 0) {
        return FAILURE;
    }

    zend_fcall_info_args_clear(fci, !argc);

    if (argc) {
        fci->param_count = argc;
        fci->params = (zval ***) erealloc(fci->params, fci->param_count * sizeof(zval **));

        for (i = 0; i < argc; ++i) {
            arg = va_arg(*argv, zval **);
            fci->params[i] = arg;
        }
    }

    return SUCCESS;
}
/* }}} */

static int zend_fcall_info_argn(zend_fcall_info *fci TSRMLS_DC, int argc, ...) /* {{{ */
{
   int ret;
   va_list argv;

   va_start(argv, argc);
   ret = zend_fcall_info_argv(fci TSRMLS_CC, argc, &argv);
   va_end(argv);

   return ret;
}
/* }}} */

#endif

#define PTH_RETURNVAL_USED(opline) (!((opline)->result.u.EA.type & EXT_TYPE_UNUSED))

static user_opcode_handler_t old_new_handler   = NULL;
static user_opcode_handler_t old_exit_handler  = NULL;
static user_opcode_handler_t old_init_fcall_handler = NULL;
static user_opcode_handler_t old_do_fcall_handler = NULL;

static int test_helpers_module_initialized = 0;

typedef struct {
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
} user_handler_t;

ZEND_BEGIN_MODULE_GLOBALS(test_helpers)
	user_handler_t new_handler;
	user_handler_t exit_handler;
	user_handler_t fcall_handler;
	
	HashTable *overloaded_functions;
ZEND_END_MODULE_GLOBALS(test_helpers)

ZEND_DECLARE_MODULE_GLOBALS(test_helpers)

#ifdef ZTS
#define THG(v) TSRMG(test_helpers_globals_id, zend_test_helpers_globals *, v)
#else
#define THG(v) (test_helpers_globals.v)
#endif

#ifdef COMPILE_DL_TEST_HELPERS
ZEND_GET_MODULE(test_helpers)
#endif

#undef EX
#define EX(element) execute_data->element
#define EX_T(offset) (*(temp_variable *)((char *) EX(Ts) + offset))
	
static zval *pth_get_zval_ptr(znode *node, zval **freeval, zend_execute_data *execute_data TSRMLS_DC) /* {{{ */
{
	*freeval = NULL;

	switch (node->op_type) {
	case IS_CONST:
		return &(node->u.constant);
	case IS_VAR:
		return EX_T(node->u.var).var.ptr;
	case IS_TMP_VAR:
		return (*freeval = &EX_T(node->u.var).tmp_var);
	case IS_CV:
		{
		zval ***ret = &execute_data->CVs[node->u.var];
		if (!*ret) {
				zend_compiled_variable *cv = &EG(active_op_array)->vars[node->u.var];
				if (zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len+1, cv->hash_value, (void**)ret)==FAILURE) {
					zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
					return &EG(uninitialized_zval);
				}
		}
		return **ret;
		}
	case IS_UNUSED:
	default:
		return NULL;
	}
}
/* }}} */

static void test_helpers_free_handler(zend_fcall_info *fci) /* {{{ */
{
	if (fci->function_name) {
		zval_ptr_dtor(&fci->function_name);
		fci->function_name = NULL;
	}
#if PHP_VERSION_ID >= 50300
	if (fci->object_ptr) {
		zval_ptr_dtor(&fci->object_ptr);
		fci->object_ptr = NULL;
	}
#endif
}
/* }}} */

static int pth_new_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */
{
	zval *retval, *arg;
	zend_op *opline = EX(opline);
	zend_class_entry *old_ce, **new_ce;

	if (THG(new_handler).fci.function_name == NULL) {
		if (old_new_handler) {
			return old_new_handler(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
		} else {
			return ZEND_USER_OPCODE_DISPATCH;
		}
	}

	old_ce = EX_T(opline->op1.u.var).class_entry;

	MAKE_STD_ZVAL(arg);
	ZVAL_STRINGL(arg, old_ce->name, old_ce->name_length, 1);

	zend_fcall_info_argn(&THG(new_handler).fci TSRMLS_CC, 1, &arg);
	zend_fcall_info_call(&THG(new_handler).fci, &THG(new_handler).fcc, &retval, NULL TSRMLS_CC);
	zend_fcall_info_args_clear(&THG(new_handler).fci, 1);

	convert_to_string_ex(&retval);
	if (zend_lookup_class(Z_STRVAL_P(retval), Z_STRLEN_P(retval), &new_ce TSRMLS_CC) == FAILURE) {
		if (!EG(exception)) {
			zend_throw_exception_ex(zend_exception_get_default(TSRMLS_C), -1 TSRMLS_CC, "Class %s does not exist", Z_STRVAL_P(retval));
		}
		zval_ptr_dtor(&arg);
		zval_ptr_dtor(&retval);

		return ZEND_USER_OPCODE_CONTINUE;
	}

	zval_ptr_dtor(&arg);
	zval_ptr_dtor(&retval);


	EX_T(opline->op1.u.var).class_entry = *new_ce;

	if (old_new_handler) {
		return old_new_handler(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
	} else {
		return ZEND_USER_OPCODE_DISPATCH;
	}
}
/* }}} */

static int pth_init_fcall_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */ 
{
	zend_op *opline = EX(opline);
	zval **overloaded_func_name;
	zval *function_name;
	zval *freeop;	
	zval *current_function_name;
	
	/* ZEND_INIT_FCALL_BY_NAME is called for variables and functions that haven't been defined yet. */
	
	current_function_name = &opline->op1.u.constant;
	
	/* Trying to call a function through a variable that is a CV ?*/ 
	if (!current_function_name || current_function_name->type != IS_STRING)
	{
		current_function_name = pth_get_zval_ptr(&opline->op2, &freeop, execute_data TSRMLS_CC);
		
		/* Lamdas/closures are objects of type Invokable. They have nothing 
		   to recognize them by, so they're impossible to overload. Ignore. */
		if (Z_TYPE_P(current_function_name) != IS_STRING)
			return ZEND_USER_OPCODE_DISPATCH;
			
		/* Do the normal thing if we haven't overloaded this particular function. 
		   @TODO: Is there anyway we can speed this up more? By using zend_hash_quick_find, for instance? */
		if (zend_hash_find(THG(overloaded_functions), Z_STRVAL_P(current_function_name), Z_STRLEN_P(current_function_name) +1, (void **) &overloaded_func_name) != SUCCESS)
			return ZEND_USER_OPCODE_DISPATCH;
		
		/* Don't mess with the CV, instead - mess with the opline and make it a CONST lookup */
		if (Z_TYPE_PP(overloaded_func_name) == IS_STRING)
		{
			zval *op1 = &opline->op1.u.constant;
			zval *op2 = &opline->op2.u.constant;
			
			opline->op1.op_type = IS_CONST;
			opline->op2.op_type = IS_CONST;
			
			ZVAL_STRINGL(op1, Z_STRVAL_PP(overloaded_func_name), Z_STRLEN_PP(overloaded_func_name), true);
			ZVAL_STRINGL(op2, Z_STRVAL_PP(overloaded_func_name), Z_STRLEN_PP(overloaded_func_name), true);
	
			opline->extended_value = zend_hash_func(Z_STRVAL_PP(overloaded_func_name), Z_STRLEN_PP(overloaded_func_name) + 1);
		}
	}
	else 
	{
		// Couldn't find the function we're calling in our overload registry? Let the original opcode handler handle it
		if (zend_hash_find(THG(overloaded_functions), Z_STRVAL_P(current_function_name), Z_STRLEN_P(current_function_name) +1, (void **) &overloaded_func_name) != SUCCESS)
			return ZEND_USER_OPCODE_DISPATCH;
			
		// Simple function -> function overload
		if (Z_TYPE_PP(overloaded_func_name) == IS_STRING)
		{
			efree(current_function_name->value.str.val);
		
			current_function_name->value.str.val = Z_STRVAL_PP(overloaded_func_name);
			current_function_name->value.str.len = Z_STRLEN_PP(overloaded_func_name) - 1;
	
			opline->op2.op_type = IS_CONST;
			ZVAL_STRINGL(&opline->op2.u.constant, Z_STRVAL_PP(overloaded_func_name), Z_STRLEN_PP(overloaded_func_name)+1, true);
			opline->extended_value = zend_hash_func(Z_STRVAL_PP(overloaded_func_name), Z_STRLEN_PP(overloaded_func_name));
		}
	}
	
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int pth_do_fcall_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */
{	
	zend_op *opline = EX(opline);
	zval **overloaded_func_name;
	zval *retval;
	
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error;
			
	zval *current_function_name = &opline->op1.u.constant;

	/* Do the normal thing if we haven't overloaded this particular function. */
	if (zend_hash_find(THG(overloaded_functions), Z_STRVAL_P(current_function_name), Z_STRLEN_P(current_function_name) +1, (void **) &overloaded_func_name) != SUCCESS)
		return ZEND_USER_OPCODE_DISPATCH;
		
	zval *of = *overloaded_func_name;	

	/* Instead of doing the actual function call, we'll call our own overload 
	   function and pretend the original function was called. */
	if (zend_fcall_info_init(of, 0, &fci, &fcc, NULL, &is_callable_error TSRMLS_CC) == SUCCESS)
	{	
		zend_uint i=0;
		zval ***params;
		zval *array_of_params;
		
		/* Collect the arguments in a PHP array. I'm pretty sure
		   there is a nicer way of doing this, but this was the only 
		   way I could make it work properly at this time. */
		void **p = zend_vm_stack_push_args(opline->extended_value TSRMLS_CC);

		ulong arg_count = opline->extended_value;
		zend_fcall_info_args_clear(&fci, !arg_count);

		MAKE_STD_ZVAL(array_of_params);
		array_init(array_of_params);
		
		while (arg_count > 0)
		{
			zval *argument = *(p-arg_count);
			
			if (argument)
				add_next_index_zval(array_of_params, argument);
			arg_count--;
		}
		
		/* Do the function call and store the result where the interpreter expects it. */
		zend_fcall_info_args(&fci, array_of_params);
		zend_fcall_info_call(&fci, &fcc, &EX_T(opline->result.u.var).var.ptr, NULL TSRMLS_CC);	

		zend_fcall_info_args_clear(&fci, 1);
		zval_ptr_dtor(&array_of_params);

		if (!PTH_RETURNVAL_USED(opline) && EX_T(opline->result.u.var).var.ptr)
		{
			zval_ptr_dtor(&EX_T(opline->result.u.var).var.ptr);
		}
	
	} 
	else
		efree(is_callable_error);	

	/* No need to do the original opcode now, carry on with the next opcode. */
	EX(opline)++;
	return ZEND_USER_OPCODE_CONTINUE;
}

static int pth_exit_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */
{
	zval *msg, *freeop;
	zval *retval;

	if (THG(exit_handler).fci.function_name == NULL) {
		if (old_exit_handler) {
			return old_exit_handler(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
		} else {
			return ZEND_USER_OPCODE_DISPATCH;
		}
	}

	msg = pth_get_zval_ptr(&EX(opline)->op1, &freeop, execute_data TSRMLS_CC);

	if (msg) {
		zend_fcall_info_argn(&THG(exit_handler).fci TSRMLS_CC, 1, &msg);
	}
	zend_fcall_info_call(&THG(exit_handler).fci, &THG(exit_handler).fcc, &retval, NULL TSRMLS_CC);
	zend_fcall_info_args_clear(&THG(exit_handler).fci, 1);

	convert_to_boolean(retval);
	if (Z_LVAL_P(retval)) {
		zval_ptr_dtor(&retval);
		if (old_exit_handler) {
			return old_exit_handler(ZEND_OPCODE_HANDLER_ARGS_PASSTHRU);
		} else {
			return ZEND_USER_OPCODE_DISPATCH;
		}
	} else {
		zval_ptr_dtor(&retval);
		EX(opline)++;
		return ZEND_USER_OPCODE_CONTINUE;
	}
}
/* }}} */

static void php_test_helpers_init_globals(zend_test_helpers_globals *globals) /* {{{ */
{
	globals->new_handler.fci.function_name = NULL;
	globals->exit_handler.fci.function_name = NULL;
	
#if PHP_VERSION_ID >= 50300
	globals->new_handler.fci.object_ptr = NULL;
	globals->exit_handler.fci.object_ptr = NULL;
#endif
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
static PHP_MINIT_FUNCTION(test_helpers)
{
	if (test_helpers_module_initialized) {
		/* This should never happen as it is handled by the module loader, but let's play safe */
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "test_helpers had already been initialized! Either load it as regular PHP extension or zend_extension");
		return FAILURE;
	}

	ZEND_INIT_MODULE_GLOBALS(test_helpers, php_test_helpers_init_globals, NULL);
	old_new_handler = zend_get_user_opcode_handler(ZEND_NEW);
	zend_set_user_opcode_handler(ZEND_NEW, pth_new_handler);

	old_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
	zend_set_user_opcode_handler(ZEND_EXIT, pth_exit_handler);
	
	old_init_fcall_handler = zend_get_user_opcode_handler(ZEND_INIT_FCALL_BY_NAME);
	zend_set_user_opcode_handler(ZEND_INIT_FCALL_BY_NAME, pth_init_fcall_handler);
	
	old_do_fcall_handler = zend_get_user_opcode_handler(ZEND_DO_FCALL);
	zend_set_user_opcode_handler(ZEND_DO_FCALL, pth_do_fcall_handler);
		
	test_helpers_module_initialized = 1;

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
static PHP_RINIT_FUNCTION(test_helpers)
{
	ALLOC_HASHTABLE(THG(overloaded_functions));
	zend_hash_init(THG(overloaded_functions), 0, NULL, ZVAL_PTR_DTOR, 0);

	return SUCCESS;
}
/* }}} */

static int pth_restore_overloaded_functions();

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
static PHP_RSHUTDOWN_FUNCTION(test_helpers)
{
	test_helpers_free_handler(&THG(new_handler).fci TSRMLS_CC);
	test_helpers_free_handler(&THG(exit_handler).fci TSRMLS_CC);

	pth_restore_overloaded_functions();

	zend_hash_destroy(THG(overloaded_functions));
	FREE_HASHTABLE(THG(overloaded_functions));
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
static PHP_MINFO_FUNCTION(test_helpers)
{
	char *conflict_text;

	if (pth_new_handler != zend_get_user_opcode_handler(ZEND_NEW)) {
		conflict_text = "Yes. The work-around was NOT enabled. Please make sure test_helpers was loaded as zend_extension AFTER conflicting extensions like Xdebug!";
	} else if (old_new_handler != NULL) {
		conflict_text = "Yes, work-around enabled";
	} else {
		conflict_text = "No conflict detected";
	}
	php_info_print_table_start();
	php_info_print_table_header(2, "test_helpers support", "enabled");
	php_info_print_table_row(2, "Conflicting extension found", conflict_text);
	php_info_print_table_end();
}
/* }}} */

static void overload_helper(user_opcode_handler_t op_handler, int opcode, user_handler_t *handler, INTERNAL_FUNCTION_PARAMETERS) /* {{{ */
{
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "f", &fci, &fcc) == FAILURE) {
		return;
	}

	if (op_handler != zend_get_user_opcode_handler(opcode)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "A conflicting extension was detected. Make sure to load test_helpers as zend_extension after other extensions");
	}

	test_helpers_free_handler(&handler->fci TSRMLS_CC);

	handler->fci = fci;
	handler->fcc = fcc;
	Z_ADDREF_P(handler->fci.function_name);
#if PHP_VERSION_ID >= 50300
	if (handler->fci.object_ptr) {
		Z_ADDREF_P(handler->fci.object_ptr);
	}
#endif

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool set_new_overload(callback cb)
   Register a callback, called on instantiation of a new object */
static PHP_FUNCTION(set_new_overload)
{
	overload_helper(pth_new_handler, ZEND_NEW, &THG(new_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool set_exit_overload(callback cb)
   Register a callback, called on exit()/die() */
static PHP_FUNCTION(set_exit_overload)
{	
	overload_helper(pth_exit_handler, ZEND_EXIT, &THG(exit_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

static void unset_overload_helper(user_handler_t *handler, INTERNAL_FUNCTION_PARAMETERS) /* {{{ */
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	test_helpers_free_handler(&handler->fci TSRMLS_CC);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool unset_new_overload()
   Remove the current new handler */
static PHP_FUNCTION(unset_new_overload)
{
	unset_overload_helper(&THG(new_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool unset_exit_overload()
   Remove the current exit handler */
static PHP_FUNCTION(unset_exit_overload)
{
	unset_overload_helper(&THG(exit_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto int pth_overload_function 
   Prepare data structures for overloading a function. */
static int pth_overload_function(HashTable *table, char *orig, int orig_len, zval *overload_function TSRMLS_DC)
{
	zend_function *func, *dummy_func;
	
	// See if the function even exists
	if (zend_hash_find(table, orig, orig_len + 1, (void **) &func) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s(%s, ...) failed: %s does not exist!",
						get_active_function_name(TSRMLS_C),
						orig, orig);
		return FAILURE;
	}
	
	// Make sure the overload doesn't already exist
	if (zend_hash_find(THG(overloaded_functions), orig, orig_len + 1, (void **) &dummy_func) == SUCCESS) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s(%s, ...) failed: %s already overloaded!",
							get_active_function_name(TSRMLS_C),
							orig, orig, orig);
		return FAILURE;
	}
	
	// Add it to the overload table
	Z_ADDREF_P(overload_function);
	if (zend_hash_add(THG(overloaded_functions), orig, orig_len + 1, (void **) &overload_function, sizeof(zval *), NULL ) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Cannot overload %s() due to internal error", orig);
		return FAILURE;
	}
		
	return SUCCESS;
}
/* }}} */

static int pth_restore_overloaded_functions() /* {{{ */
{
	zend_hash_clean(THG(overloaded_functions));
		
	return SUCCESS;
}
/* }}} */

/* {{{ proto void restore_functions()
	Clear out the overload registry so that original functions will be called again 
*/
static PHP_FUNCTION(restore_functions)
{
	int success;
	
	success = pth_restore_overloaded_functions();
	
	if (success == FAILURE)
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "%s() was unable to restore (all) overloaded functions.", get_active_function_name(TSRMLS_C));
}
/* }}} */

/* {{{ proto bool overload_function(string func_name, string overload_func_name)
   Overloads func_name with overload_func_name. Whenever func_name is called, overload_func_name
   is actually executed. This is mainly useful in unittests to stub out untested functions but also
   to provide fixtures that are system/time dependant (like date() or time()).
*/
PHP_FUNCTION(overload_function)
{
	char *orig_fname, *lower_orig, *overload_name;
	int orig_fname_len;
	
	zval *overload_function;
	int success;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &orig_fname, &orig_fname_len, &overload_function) == FAILURE) {
		return;
	}

	lower_orig = zend_str_tolower_dup(orig_fname, orig_fname_len);
	
	if (!zend_is_callable(overload_function, IS_CALLABLE_CHECK_SILENT, NULL))
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Given callback not callable");
		RETURN_FALSE;
	}
	
	success = pth_overload_function(EG(function_table), lower_orig, orig_fname_len, overload_function TSRMLS_CC);

	efree(lower_orig);

	if (success == SUCCESS) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ arginfo */
/* {{{ unset_new_overload */
ZEND_BEGIN_ARG_INFO(arginfo_unset_new_overload, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ unset_exit_overload */
ZEND_BEGIN_ARG_INFO(arginfo_unset_exit_overload, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ set_new_overload */
ZEND_BEGIN_ARG_INFO(arginfo_set_new_overload, 0)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ rename_function */
ZEND_BEGIN_ARG_INFO(arginfo_overload_function, 0)
	ZEND_ARG_INFO(0, func_name)
	ZEND_ARG_INFO(0, overload_func_name)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ set_exit_overload */
ZEND_BEGIN_ARG_INFO(arginfo_set_exit_overload, 0)
	ZEND_ARG_INFO(0, "callback")
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ restore_renamed_functions */
ZEND_BEGIN_ARG_INFO(arginfo_restore_functions, 0)
ZEND_END_ARG_INFO()
/* }}} */
/* }}} */

/* {{{ test_helpers_functions[]
 */
static const zend_function_entry test_helpers_functions[] = {
	PHP_FE(unset_new_overload, arginfo_unset_new_overload)
	PHP_FE(set_new_overload, arginfo_set_new_overload)
	PHP_FE(unset_exit_overload, arginfo_unset_exit_overload)
	PHP_FE(set_exit_overload, arginfo_set_exit_overload)
	PHP_FE(overload_function, arginfo_overload_function)
	PHP_FE(restore_functions, arginfo_restore_functions)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ test_helpers_module_entry
 */
zend_module_entry test_helpers_module_entry = {
	STANDARD_MODULE_HEADER,
	"test_helpers",
	test_helpers_functions,
	PHP_MINIT(test_helpers),
	NULL,
	PHP_RINIT(test_helpers),
	PHP_RSHUTDOWN(test_helpers),
	PHP_MINFO(test_helpers),
	TEST_HELPERS_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

static int test_helpers_zend_startup(zend_extension *extension) /* {{{ */
{
	return zend_startup_module(&test_helpers_module_entry);
}
/* }}} */

#ifndef ZEND_EXT_API
#define ZEND_EXT_API    ZEND_DLEXPORT
#endif
ZEND_EXTENSION();

zend_extension zend_extension_entry = {
	"test_helpers",
	TEST_HELPERS_VERSION,
	"Johannes Schlueter, Scott MacVicar, Sebastian Bergmann, Mathieu Kooiman",
	"http://github.com/johannes/php-test-helpers",
	"Copyright (c) 2009-2011",
	test_helpers_zend_startup,
	NULL,           /* shutdown_func_t */
	NULL,           /* activate_func_t */
	NULL,           /* deactivate_func_t */
	NULL,           /* message_handler_func_t */
	NULL,           /* op_array_handler_func_t */
	NULL,           /* statement_handler_func_t */
	NULL,           /* fcall_begin_handler_func_t */
	NULL,           /* fcall_end_handler_func_t */
	NULL,           /* op_array_ctor_func_t */
	NULL,           /* op_array_dtor_func_t */
	STANDARD_ZEND_EXTENSION_PROPERTIES
};

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
