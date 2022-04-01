//
// Created by hujianzhe
//

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
	short type;
	unsigned short port;
	const char* user;
	const char* pwd;
	const char* ip;
	const char* db_name;
	const char* error_msg;
	const char* url;
	size_t url_strlen;
	time_t last_active_timestamp_sec;
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
	short has_result_set;
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
DBHandle_t* dbCreateHandle(const char* dbtype) {
	int init_ok = 0;
	DBHandle_t* handle = (DBHandle_t*)malloc(sizeof(DBHandle_t));
	if (!handle) {
		return NULL;
	}
	handle->type = dbname_to_dbtype(dbtype);
	handle->last_active_timestamp_sec = 0;
	handle->url_strlen = 0;
	handle->url = handle->user = handle->pwd = handle->ip = handle->db_name = NULL;
	handle->error_msg = "";
	handle->stmts = NULL;
	handle->stmt_cnt = 0;
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (!mysql_init(&handle->mysql.mysql)) {
				break;
			}
			/* 
			 * mysql_thread_init() is automatically called by mysql_init() 
			 */
			init_ok = 1;
			break;
		}
		#endif
	}
	if (!init_ok) {
		free(handle);
		return NULL;
	}
	return handle;
}

static void dbCloseStmt(DBStmt_t* stmt);
void dbCloseHandle(DBHandle_t* handle) {
	size_t i;
	if (!handle) {
		return;
	}
	free((void*)handle->url);

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
	free(handle);
}

DB_RETURN dbSetConnectArg(DBHandle_t* handle, const char* ip, unsigned short port, const char* user, const char* pwd, const char* dbname) {
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
			return DB_ERROR;
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
		handle->error_msg = "no memory";
		return DB_ERROR;
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
	return DB_SUCCESS;
}

DB_RETURN dbConnect(DBHandle_t* handle, int timeout_sec) {
	DB_RETURN res;
	if (handle->last_active_timestamp_sec != 0) {
		return DB_SUCCESS;
	}
	res = DB_ERROR;
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
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
			if (mysql_set_character_set(&handle->mysql.mysql, "utf8")) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
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

DB_RETURN dbPing(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
	switch (handle->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			if (mysql_ping(&handle->mysql.mysql)) {
				handle->error_msg = mysql_error(&handle->mysql.mysql);
				break;
			}
			handle->last_active_timestamp_sec = time(NULL);
			res = DB_SUCCESS;
			break;
		}
		#endif
	}
	return res;
}

const char* dbHandleErrorMessage(DBHandle_t* handle) {
	return handle->error_msg;
}

/* transaction */
DB_RETURN dbEnableAutoCommit(DBHandle_t* handle, int bool_val) {
	DB_RETURN res = DB_ERROR;
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
	return res;
}

DB_RETURN dbStartTransaction(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
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
	return res;
}

DB_RETURN dbCommit(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
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
	return res;
}

DB_RETURN dbRollback(DBHandle_t* handle) {
	DB_RETURN res = DB_ERROR;
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

DBStmt_t* dbSQLPrepareExecute(DBHandle_t* handle, const char* sql, size_t sqllen, DBExecuteParam_t* param, unsigned short paramcnt) {
	DB_RETURN res = DB_ERROR;
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
		stmt->result_set_idx = 0;
		stmt->idle = 0;
		return stmt;
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
    return res;
}

int dbFetchResult(DBStmt_t* stmt, DBResultParam_t* param, unsigned short paramcnt) {
	int res = -1;
	do {
		if (stmt->has_result_set) {
			break;
		}
		res = dbGetResult(stmt);
		if (res > 0) {
			stmt->has_result_set = 1;
			res = -1;
			break;
		}
		return res;
	} while (0);

	switch (stmt->type) {
		#ifdef DB_ENABLE_MYSQL
		case DB_TYPE_MYSQL:
		{
			/* bind result param */
			if (stmt->mysql.result_field_count) {
				unsigned short i;
				for (i = 0; i < paramcnt && i < stmt->mysql.result_field_count; ++i) {
					MYSQL_FIELD* field = mysql_fetch_field(stmt->mysql.result_field_meta);
					if (field) {
						MYSQL_BIND* bind = stmt->mysql.result_field_param + i;
						bind->buffer_type = field->type;
						bind->buffer = param[i].buffer;
						bind->buffer_length = (unsigned long)(param[i].buffer_length);
						if (param[i].value_length) {
							*param[i].value_length = 0;
							if (sizeof(*(bind->length)) == sizeof(*(param[i].value_length)))
								bind->length = (unsigned long*)(param[i].value_length);
							else
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
					if (sizeof(*(param[0].value_length)) != sizeof(*(((MYSQL_BIND*)0)->length))) {
						unsigned short i;
						for (i = 0; i < paramcnt && i < stmt->mysql.result_field_count; ++i) {
							if (param[i].value_length) {
								*param[i].value_length = param[i].mysql_value_length;
							}
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
	if (stmt->has_result_set) {
		stmt->has_result_set = 0;
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
