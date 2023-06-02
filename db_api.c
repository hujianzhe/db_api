//
// Created by hujianzhe
//

#if defined(_WIN32) || defined(_WIN64)
	#include <winsock2.h>
	#include <windows.h>
#endif

#ifdef DB_ENABLE_MYSQL
	#if defined(_WIN32) || defined(_WIN64)
		#include <mysql.h>
		#pragma comment(lib, "libmysql.lib")/* you need copy libmysql.dll to your exe path */
	#else
		#include <mysql/mysql.h>
	#endif
#endif
#include "db_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
	DB_TYPE_RESERVED,
#ifdef DB_ENABLE_MYSQL
	DB_TYPE_MYSQL,
#endif
};

/* HANDLE */
typedef struct DBHandle_t {
	unsigned char type;
	unsigned char inner_init_ok;
	unsigned short port;
	const char* user;
	const char* pwd;
	const char* ip;
	const char* db_name;
	const char* error_msg;
	const char* url;
	size_t url_strlen;
	time_t last_active_timestamp_sec;
	short auto_commit;
	short trans_open;
	struct DBStmt_t** stmts;
	size_t stmt_cnt;
	union {
		char reserved[1];
#ifdef DB_ENABLE_MYSQL
		struct {
			MYSQL mysql;
		} mysql;
#endif
	};
} DBHandle_t;

/* STMT */
typedef struct DBStmt_t {
	short type;
	short idle;
	const char* error_msg;
	char has_result_set;
	char get_result_set_ret;
	short result_set_idx;
	union {
		char reserved[1];
#ifdef DB_ENABLE_MYSQL
		struct {
			MYSQL_STMT* stmt;
			unsigned short result_field_count;
			MYSQL_RES* result_field_meta;
			MYSQL_BIND* result_field_param;
		} mysql;
#endif
	};
} DBStmt_t;

#ifdef __cplusplus
extern "C" {
#endif

static int dbname_to_dbtype(const char* name) {
#ifdef DB_ENABLE_MYSQL
	if (!strcmp(name, "mysql"))
		return DB_TYPE_MYSQL;
#endif
	return DB_TYPE_RESERVED;
}

#ifdef DB_ENABLE_MYSQL
static enum enum_field_types type_map_to_mysql[] = {
	MYSQL_TYPE_TINY,
	MYSQL_TYPE_SHORT,
	MYSQL_TYPE_LONG,
	MYSQL_TYPE_LONGLONG,
	MYSQL_TYPE_FLOAT,
	MYSQL_TYPE_DOUBLE,
	MYSQL_TYPE_VAR_STRING,
	MYSQL_TYPE_BLOB,
};

static MYSQL_TIME* tm2mysqltime(const struct tm* tm, MYSQL_TIME* mt) {
	mt->year = tm->tm_year;
	mt->month = tm->tm_mon;
	mt->day = tm->tm_mday;
	mt->hour = tm->tm_hour;
	mt->minute = tm->tm_min;
	mt->second = tm->tm_sec;
	mt->second_part = 0;
	mt->time_type = MYSQL_TIMESTAMP_DATETIME;
	return mt;
}

static int mysql_type_to_utype(int mysql_field_type) {
	switch (mysql_field_type) {
		case MYSQL_TYPE_TINY:
			return DB_FIELD_TYPE_TINY;

		case MYSQL_TYPE_SHORT:
			return DB_FIELD_TYPE_SMALLINT;

		case MYSQL_TYPE_LONG:
			return DB_FIELD_TYPE_INT;

		case MYSQL_TYPE_LONGLONG:
			return DB_FIELD_TYPE_BIGINT;

		case MYSQL_TYPE_FLOAT:
			return DB_FIELD_TYPE_FLOAT;

		case MYSQL_TYPE_DOUBLE:
			return DB_FIELD_TYPE_DOUBLE;

		case MYSQL_TYPE_VAR_STRING:
			return DB_FIELD_TYPE_VARCHAR;

		case MYSQL_TYPE_BLOB:
			return DB_FIELD_TYPE_BLOB;
	}
	return DB_FIELD_TYPE_UNKNOWN;
}
#endif

/* env */
DB_RETURN dbInitEnv(const char* dbtype) {
	DB_RETURN res = DB_ERROR;
	switch (dbname_to_dbtype(dbtype)) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (mysql_library_init(0, NULL, NULL))
				break;
			if (mysql_thread_safe() != 1) {
				mysql_library_end();
				break;
			}
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	return res;
}

void dbCleanEnv(const char* dbtype) {
	switch (dbname_to_dbtype(dbtype)) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			mysql_library_end();
			break;
		}
		#endif
	}
}

DB_RETURN dbAllocTls(void) {
	#ifdef DB_ENABLE_MYSQL
	return mysql_thread_init() ? DB_ERROR : DB_SUCCESS;
	#endif
	return DB_SUCCESS;
}

void dbFreeTls(void) {
	#ifdef DB_ENABLE_MYSQL
	mysql_thread_end();
	#endif
}

/* handle */
static void db_init_handle(DBHandle_t* handle) {
	handle->last_active_timestamp_sec = 0;
	handle->error_msg = "";
	handle->auto_commit = 0;
	handle->trans_open = 0;
	handle->stmts = NULL;
	handle->stmt_cnt = 0;
	handle->inner_init_ok = 0;
}

static DBHandle_t* db_assign_url(DBHandle_t* handle, const char* ip, unsigned short port, const char* user, const char* pwd, const char* dbname) {
	size_t schemalen, iplen, userlen, pwdlen, dbnamelen;
	size_t url_strlen, arg_strlen;
	char* url;
	const char* schema;
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			schema = "mysql";
			schemalen = sizeof("mysql") - 1;
			break;
		}
		#endif
		default:
		{
			return NULL;
		}
	}
	iplen = strlen(ip);
	userlen = strlen(user);
	pwdlen = strlen(pwd);
	dbnamelen = strlen(dbname);
	// mysql://vivie:vivie970126@127.0.0.1:3306/filemeta
	url_strlen = schemalen + 3 + userlen + 1 + pwdlen + 1 + iplen + 1 + 5 + 1 + dbnamelen;
	arg_strlen = userlen + 1 + pwdlen + 1 + iplen + 1 + dbnamelen;
	url = (char*)malloc(url_strlen + 1 + arg_strlen + 1);
	if (!url) {
		return NULL;
	}
	sprintf(url, "%s://%s:%s@%s:%u/%s", schema, user, pwd, ip, port, dbname);
	url[url_strlen] = 0;
	handle->url = url;
	handle->url_strlen = url_strlen;
	handle->user = url + url_strlen + 1;
	strcpy((char*)handle->user, user);
	handle->pwd = handle->user + userlen + 1;
	strcpy((char*)handle->pwd, pwd);
	handle->ip = handle->pwd + pwdlen + 1;
	strcpy((char*)handle->ip, ip);
	handle->port = port;
	handle->db_name = handle->ip + iplen + 1;
	strcpy((char*)handle->db_name, dbname);
	return handle;
}

DBHandle_t* dbOpenHandle(const char* dbtype, const char* ip, unsigned short port, const char* user, const char* pwd, const char* dbname) {
	DBHandle_t* handle;
	int handle_type = dbname_to_dbtype(dbtype);
	if (DB_TYPE_RESERVED == handle_type) {
		return NULL;
	}
	handle = (DBHandle_t*)malloc(sizeof(DBHandle_t));
	if (!handle) {
		return NULL;
	}
	handle->type = handle_type;
	if (!pwd) {
		pwd = "";
	}
	if (!dbname) {
		dbname = "";
	}
	if (!db_assign_url(handle, ip, port, user, pwd, dbname)) {
		free(handle);
		return NULL;
	}
	db_init_handle(handle);
	return handle;
}

static void dbCloseStmt(DBStmt_t* stmt);
static void db_free_inner_resources(DBHandle_t* handle) {
	size_t i;
	if (!handle->inner_init_ok) {
		return;
	}
	handle->inner_init_ok = 0;
	for (i = 0; i < handle->stmt_cnt; ++i) {
		dbCloseStmt(handle->stmts[i]);
	}
	free(handle->stmts);
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			mysql_close(&handle->mysql.mysql);
			break;
		}
		#endif
	}
}
void dbCloseHandle(DBHandle_t* handle) {
	if (!handle) {
		return;
	}
	db_free_inner_resources(handle);
	free((void*)handle->url);
	free(handle);
}

static DB_RETURN db_connect(DBHandle_t* handle, int timeout_sec) {
	DB_RETURN res;
	if (handle->last_active_timestamp_sec != 0) {
		time_t cur_sec = time(NULL);
		if (handle->last_active_timestamp_sec <= cur_sec &&
			handle->last_active_timestamp_sec + 3600 > cur_sec)
		{
			return DB_SUCCESS;
		}
		db_free_inner_resources(handle);
		db_init_handle(handle);
	}
	res = DB_ERROR;
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			// char opt_reconnect = 1;
			if (!handle->inner_init_ok) {
				if (!mysql_init(&handle->mysql.mysql)) {
					handle->error_msg = "mysql_init api error";
					break;
				}
				handle->inner_init_ok = 1;
			}
			/* 
			 * mysql_thread_init() is automatically called by mysql_init() 
			 */
			if (timeout_sec > 0) {
				if (mysql_options(&handle->mysql.mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_sec)) {
					handle->error_msg = mysql_error(&handle->mysql.mysql);
					break;
				}
			}
			if (!mysql_real_connect(&handle->mysql.mysql, handle->ip, handle->user, handle->pwd, handle->db_name, handle->port, NULL, CLIENT_MULTI_STATEMENTS)) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			/* mysql_query(env->hEnv,"set names utf8"); */
			if (mysql_set_character_set(&handle->mysql.mysql, "utf8mb4")) {
				if (mysql_set_character_set(&handle->mysql.mysql, "utf8")) {
					handle->error_msg = mysql_error(&handle->mysql.mysql);
					break;
				}
			}
			/*
			if (mysql_options(&handle->mysql.mysql, MYSQL_OPT_RECONNECT, &opt_reconnect)) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			*/
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	if (DB_SUCCESS == res) {
		handle->last_active_timestamp_sec = time(NULL);
	}
	return res;
}

const char* dbHandleErrorMessage(DBHandle_t* handle) {
	return handle->error_msg;
}

/* transaction */
DB_RETURN dbEnableAutoCommit(DBHandle_t* handle, int bool_val) {
	DB_RETURN res = DB_ERROR;
	if (handle->auto_commit && bool_val) {
		return DB_SUCCESS;
	}
	if (!handle->auto_commit && !bool_val) {
		return DB_SUCCESS;
	}
	if (db_connect(handle, 3000) == DB_ERROR) {
		return DB_ERROR;
	}
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (mysql_autocommit(&handle->mysql.mysql, bool_val != 0)) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	if (DB_SUCCESS == res) {
		handle->auto_commit = bool_val;
	}
	return res;
}

DB_RETURN dbStartTransaction(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
	if (handle->trans_open) {
		return DB_SUCCESS;
	}
	if (db_connect(handle, 3000) == DB_ERROR) {
		return DB_ERROR;
	}
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (mysql_query(&handle->mysql.mysql, "start transaction")) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	if (DB_SUCCESS == res) {
		handle->trans_open = 1;
	}
	return res;
}

DB_RETURN dbCommit(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
	if (!handle->trans_open) {
		return DB_SUCCESS;
	}
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (mysql_commit(&handle->mysql.mysql)) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	if (DB_SUCCESS == res) {
		handle->trans_open = 0;
	}
	return res;
}

DB_RETURN dbRollback(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
	if (!handle->trans_open) {
		return DB_SUCCESS;
	}
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (mysql_rollback(&handle->mysql.mysql)) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	if (DB_SUCCESS == res) {
		handle->trans_open = 0;
	}
	return res;
}

/* SQL execute */
static DBStmt_t* dbAllocStmt(DBHandle_t* handle) {
	DBStmt_t* stmt, **stmts_buf;
	int init_ok;
	size_t i;
	for (i = 0; i < handle->stmt_cnt; ++i) {
		stmt = handle->stmts[i];
		if (stmt->idle) {
			return stmt;
		}
	}
	stmts_buf = (DBStmt_t**)realloc(handle->stmts, sizeof(handle->stmts[0]) * (handle->stmt_cnt + 1));
	if (!stmts_buf) {
		handle->error_msg = "not enough memory";
		return NULL;
	}
	handle->stmts = stmts_buf;
	stmt = (DBStmt_t*)malloc(sizeof(DBStmt_t));
	if (!stmt) {
		handle->error_msg = "not enough memory";
		return NULL;
	}
	init_ok = 0;
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			stmt->mysql.stmt = mysql_stmt_init(&handle->mysql.mysql);
			if (NULL == stmt->mysql.stmt) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			stmt->mysql.result_field_count = 0;
			stmt->mysql.result_field_meta = NULL;
			stmt->mysql.result_field_param = NULL;
			init_ok = 1;
			break;
		}
		#endif
	}
	if (init_ok) {
		stmt->type = handle->type;
		stmt->idle = 1;
		stmt->error_msg = "";
		stmt->has_result_set = 0;
		stmt->get_result_set_ret = 0;
		stmt->result_set_idx = 0;
		handle->stmts[handle->stmt_cnt] = stmt;
		handle->stmt_cnt += 1;
		return stmt;
	}
	free(stmt);
	return NULL;
}

const char* dbStmtErrorMessage(DBStmt_t* stmt) {
	return stmt->error_msg;
}

unsigned int dbStmtSQLErrno(DBStmt_t* stmt) {
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
			return mysql_stmt_errno(stmt->mysql.stmt);
		#endif
	}
	return 0;
}

const char* dbStmtSQLState(DBStmt_t* stmt) {
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
			return mysql_stmt_sqlstate(stmt->mysql.stmt);
		#endif
	}
	return NULL;
}

int dbSQLIsSelect(const char* sql, size_t sqllen) {
	if (sqllen < 6) {
		return 0;
	}
	return !memcmp(sql, "select", 6) || !memcmp(sql, "SELECT", 6);
}

DBStmt_t* dbSQLPrepareExecute(DBHandle_t* handle, const char* sql, size_t sqllen, DBExecuteParam_t* param, unsigned short paramcnt) {
	DB_RETURN res = DB_ERROR;
	if (db_connect(handle, 3000) == DB_ERROR) {
		return NULL;
	}
	DBStmt_t* stmt = dbAllocStmt(handle);
	if (!stmt) {
		return NULL;
	}
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			unsigned short exec_param_count;
			/* prepare */
			if (mysql_stmt_prepare(stmt->mysql.stmt, sql, (unsigned long)sqllen)) {
				stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
				break;
			}
			exec_param_count = mysql_stmt_param_count(stmt->mysql.stmt);
			if (exec_param_count) {
				unsigned short i;
				MYSQL_BIND* exec_params = (MYSQL_BIND*)calloc(1, sizeof(MYSQL_BIND) * exec_param_count);
				if (!exec_params) {
					stmt->error_msg = "not enough memory to alloc MYSQL_BIND";
					break;
				}
				/* bind execute param */
				for (i = 0; i < paramcnt && i < exec_param_count; ++i) {
					MYSQL_BIND* bind = exec_params + i;
					if (param[i].field_type < 0 ||
						param[i].field_type >= sizeof(type_map_to_mysql) / sizeof(type_map_to_mysql[0]))
					{
						stmt->error_msg = "set bind param field type invalid";
						break;
					}
					bind->buffer_type = type_map_to_mysql[param[i].field_type];
					bind->buffer = (void*)(param[i].buffer);
					bind->buffer_length = (unsigned long)(param[i].buffer_length);
				}
				if (mysql_stmt_bind_param(stmt->mysql.stmt, exec_params)) {
					stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
					break;
				}

				if (mysql_stmt_execute(stmt->mysql.stmt)) {
					free(exec_params);
					break;
				}
				free(exec_params);
			}
			else if (mysql_stmt_execute(stmt->mysql.stmt)) {
				stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
				break;
			}
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	if (DB_SUCCESS == res) {
		stmt->has_result_set = 0;
		stmt->get_result_set_ret = 0;
		stmt->result_set_idx = 0;
		stmt->idle = 0;
		return stmt;
	}
	else {
		handle->error_msg = stmt->error_msg;
	}
	return NULL;
}

/* result set */
long long dbAutoIncrementValue(DBStmt_t* stmt) {
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			return mysql_stmt_insert_id(stmt->mysql.stmt);
		}
		#endif
		default:
			return -1;
	}
}

long long dbAffectedRows(DBStmt_t* stmt) {
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			my_ulonglong affectRows = mysql_stmt_affected_rows(stmt->mysql.stmt);
			if (affectRows != MYSQL_COUNT_ERROR)
				return affectRows;
			else
			{
				stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
				return -1;
			}
			break;
		}
		#endif
		default:
			return -1;
	}
}

static int dbGetResult(DBStmt_t* stmt) {
	int res = -1;

	if (stmt->has_result_set) {
		return stmt->get_result_set_ret;
	}
	stmt->has_result_set = 1;

	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			short result_field_count;
			/* get result */
			if (0 == stmt->result_set_idx) {
				if (mysql_stmt_store_result(stmt->mysql.stmt)) {
					stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
					break;
				}
			}
			else {
				#if MYSQL_VERSION_ID >= 50503
				int ret = mysql_stmt_next_result(stmt->mysql.stmt);
				if (-1 == ret) {
					res = 0;
					/* no more result */
					break;
				}
				else if (ret) {
					stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
					break;
				}
				#else
				break;
				#endif
			}
			/* result info */
			result_field_count = mysql_stmt_field_count(stmt->mysql.stmt);
			if (result_field_count > 0) {
				/* result meta */
				stmt->mysql.result_field_meta = mysql_stmt_result_metadata(stmt->mysql.stmt);
				if (NULL == stmt->mysql.result_field_meta) {
					stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
					mysql_stmt_free_result(stmt->mysql.stmt);
					break;
				}
				/* result field */
				stmt->mysql.result_field_param = (MYSQL_BIND*)calloc(1, sizeof(MYSQL_BIND) * result_field_count);
				if (NULL == stmt->mysql.result_field_param) {
					stmt->error_msg = "not enough memory to alloc MYSQL_BIND";
					mysql_stmt_free_result(stmt->mysql.stmt);
					break;
				}
				stmt->mysql.result_field_count = result_field_count;
				res = 1;
			}
			else if (0 == result_field_count) {
				res = 0;
			}
			
			break;
		}
		#endif
    }
	if (res >= 0) {
		stmt->result_set_idx++;
	}
	stmt->get_result_set_ret = res;
    return res;
}

unsigned short dbResultFieldCount(struct DBStmt_t* stmt) {
	unsigned short count = 0;
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			int ret = dbGetResult(stmt);
			if (ret <= 0) {
				break;
			}
			return stmt->mysql.result_field_count;
		}
		#endif
	}
	return count;
}

unsigned short dbResultFieldMetaDatas(struct DBStmt_t* stmt, DBFieldMetaData_t* metas, unsigned short n) {
	unsigned short count = 0;
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			unsigned short i;
			int ret = dbGetResult(stmt);
			if (ret <= 0) {
				break;
			}
			if (!stmt->mysql.result_field_meta) {
				break;
			}
			for (i = 0; i < n; ++i) {
				MYSQL_FIELD* field = mysql_fetch_field(stmt->mysql.result_field_meta);
				if (!field) {
					break;
				}
				metas[count].type = mysql_type_to_utype(field->type);
				metas[count].length = field->length;
				metas[count].name = field->name;
				metas[count].name_length = field->name_length;
				++count;
			}
			break;
		}
		#endif
	}
	return count;
}

int dbFetchResult(DBStmt_t* stmt, DBResultParam_t* param, unsigned short paramcnt) {
	int res = dbGetResult(stmt);
	if (res <= 0) {
		return res;
	}
	res = -1;

	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			/* bind result param */
			if (stmt->mysql.result_field_count) {
				unsigned short i;
				mysql_field_seek(stmt->mysql.result_field_meta, 0);
				for (i = 0; i < paramcnt && i < stmt->mysql.result_field_count; ++i) {
					MYSQL_FIELD* field = mysql_fetch_field(stmt->mysql.result_field_meta);
					if (field) {
						MYSQL_BIND* bind = stmt->mysql.result_field_param + i;
						bind->buffer_type = field->type;
						bind->buffer = param[i].buffer;
						bind->buffer_length = (unsigned long)(param[i].buffer_length);
						if (param[i].ptr_value_length) {
							*param[i].ptr_value_length = 0;
							bind->length = &param[i].mysql_value_length;
						}
					}
					else break;
				}
				if (mysql_stmt_bind_result(stmt->mysql.stmt, stmt->mysql.result_field_param)) {
					stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
					break;
				}
			}
			/* fetch result */
			switch (mysql_stmt_fetch(stmt->mysql.stmt)) {
				case 0:
				case MYSQL_DATA_TRUNCATED:
				{
					unsigned short i;
					for (i = 0; i < paramcnt && i < stmt->mysql.result_field_count; ++i) {
						if (param[i].ptr_value_length) {
							*param[i].ptr_value_length = param[i].mysql_value_length;
						}
					}
					res = 1;
					break;
				}
				case MYSQL_NO_DATA:
					res = 0;
					break;
				default:
					stmt->error_msg = mysql_stmt_error(stmt->mysql.stmt);
			}

			break;
		}
		#endif
	}
	return res;
}

void dbFreeResult(DBStmt_t* stmt) {
	if (!stmt) {
		return;
	}
	if (stmt->has_result_set) {
		stmt->has_result_set = 0;
		stmt->get_result_set_ret = 0;
		switch (stmt->type) {
			#ifdef DB_ENABLE_MYSQL
			case DB_TYPE_MYSQL:
			{
				if (stmt->mysql.result_field_param) {
					free(stmt->mysql.result_field_param);
					stmt->mysql.result_field_param = NULL;
				}
				if (stmt->mysql.result_field_meta) {
					mysql_free_result(stmt->mysql.result_field_meta);
					stmt->mysql.result_field_meta = NULL;
				}
				stmt->mysql.result_field_count = 0;
				mysql_stmt_free_result(stmt->mysql.stmt);
				break;
			}
			#endif
		}
	}
	stmt->idle = 1;
}

static void dbCloseStmt(DBStmt_t* stmt) {
	if (!stmt) {
		return;
	}
	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			dbFreeResult(stmt);
			mysql_stmt_close(stmt->mysql.stmt);
			stmt->mysql.stmt = NULL;
			break;
		}
		#endif
	}
	free(stmt);
}

#ifdef __cplusplus
}
#endif
