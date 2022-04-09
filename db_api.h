//
// Created by hujianzhe
//

#ifndef UTIL_LIB_DB_API_H
#define UTIL_LIB_DB_API_H

#ifdef _MSC_VER
	#ifndef	__declspec_dll
		#ifdef	DECLSPEC_DLL_EXPORT
			#define	__declspec_dll						__declspec(dllexport)
		#elif	DECLSPEC_DLL_IMPORT
			#define	__declspec_dll						__declspec(dllimport)
		#else
			#define	__declspec_dll
		#endif
	#endif
#elif	defined(__GNUC__) || defined(__GNUG__)
	#ifndef _REENTRANT
		#define	_REENTRANT
	#endif
	#ifndef	__declspec_dll
		#define	__declspec_dll
	#endif
#endif

#include <stddef.h>
#include <time.h>

typedef enum DB_RETURN {
	DB_ERROR,
	DB_SUCCESS
} DB_RETURN;

enum {
	DB_FIELD_TYPE_TINY,
	DB_FIELD_TYPE_SMALLINT,
	DB_FIELD_TYPE_INT,
	DB_FIELD_TYPE_BIGINT,
	DB_FIELD_TYPE_FLOAT,
	DB_FIELD_TYPE_DOUBLE,
	DB_FIELD_TYPE_VARCHAR,
	DB_FIELD_TYPE_BLOB,
};

struct DBHandle_t;
struct DBStmt_t;

typedef struct DBResultParam_t {
	void* buffer;
	size_t buffer_length;
	size_t* value_length;
	union {
		unsigned long mysql_value_length;
	};
} DBResultParam_t;

typedef struct DBExecuteParam_t {
	int field_type;
	const void* buffer;
	size_t buffer_length;
} DBExecuteParam_t;

#ifdef __cplusplus
extern "C" {
#endif

/* env */
__declspec_dll DB_RETURN dbInitEnv(const char* dbtype);
__declspec_dll void dbCleanEnv(const char* dbtype);
__declspec_dll DB_RETURN dbAllocTls(void);
__declspec_dll void dbFreeTls(void);
/* handle */
__declspec_dll struct DBHandle_t* dbOpenHandle(const char* dbtype, const char* ip, unsigned short port, const char* user, const char* pwd, const char* dbname);
__declspec_dll void dbCloseHandle(struct DBHandle_t* handle);
__declspec_dll const char* dbHandleErrorMessage(struct DBHandle_t* handle);
/* transaction */
__declspec_dll DB_RETURN dbEnableAutoCommit(struct DBHandle_t* handle, int bool_val);
__declspec_dll DB_RETURN dbStartTransaction(struct DBHandle_t* handle);
__declspec_dll DB_RETURN dbCommit(struct DBHandle_t* handle);
__declspec_dll DB_RETURN dbRollback(struct DBHandle_t* handle);
/* SQL execute */
__declspec_dll struct DBStmt_t* dbSQLPrepareExecute(struct DBHandle_t* handle, const char* sql, size_t sqllen, DBExecuteParam_t* param, unsigned short paramcnt);
__declspec_dll const char* dbStmtErrorMessage(struct DBStmt_t* stmt);
/* result set */
__declspec_dll void dbFreeResult(struct DBStmt_t* stmt);
__declspec_dll long long dbAutoIncrementValue(struct DBStmt_t* stmt);
__declspec_dll long long dbAffectedRows(struct DBStmt_t* stmt);
/* ret < 0 err, == 0 no data, > 0 has data */
__declspec_dll int dbFetchResult(struct DBStmt_t* stmt, DBResultParam_t* param, unsigned short paramcnt);

#ifdef __cplusplus
}
#endif

#endif
