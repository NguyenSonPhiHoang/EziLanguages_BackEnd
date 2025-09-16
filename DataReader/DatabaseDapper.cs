using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;

namespace EziLanguages.DataReader
{
    public class DatabaseDapper
    {
        private readonly string connectionString;
        private const int DefaultCommandTimeout = 30; // Timeout mặc định 30 giây
        private SqlConnection _connection;
        private SqlTransaction _transaction;

        // Constructor nhận IConfiguration để lấy connection string
        public DatabaseDapper(IConfiguration configuration)
        {
            try
            {
                connectionString = configuration.GetConnectionString("DefaultConnection")
                    ?? throw new InvalidOperationException("Chuỗi kết nối không được cấu hình.");
            }
            catch (Exception)
            {
                throw; // Giữ nguyên stack trace
            }
        }
        
        // Bắt đầu transaction
        public SqlTransaction BeginTransaction()
        {
            if (_connection == null)
            {
                _connection = new SqlConnection(connectionString);
                _connection.Open();
            }

            if (_connection.State != ConnectionState.Open)
            {
                _connection.Open();
            }

            _transaction = _connection.BeginTransaction();
            return _transaction;
        }

        // Bắt đầu transaction async
        public async Task<SqlTransaction> BeginTransactionAsync()
        {
            if (_connection == null)
            {
                _connection = new SqlConnection(connectionString);
                await _connection.OpenAsync();
            }

            if (_connection.State != ConnectionState.Open)
            {
                await _connection.OpenAsync();
            }

            _transaction = _connection.BeginTransaction();
            return _transaction;
        }

        // Commit transaction
        public void CommitTransaction()
        {
            _transaction?.Commit();
            _transaction?.Dispose();
            _transaction = null;
        }

        // Rollback transaction
        public void RollbackTransaction()
        {
            _transaction?.Rollback();
            _transaction?.Dispose();
            _transaction = null;
        }

        // Truy vấn dữ liệu với stored procedure (sync)
        public IEnumerable<T> QueryStoredProcedure<T>(string storedProcedure, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.Query<T>(storedProcedure, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Truy vấn dữ liệu với stored procedure (async)
        public async Task<IEnumerable<T>> QueryStoredProcedureAsync<T>(string storedProcedure, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.QueryAsync<T>(storedProcedure, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Truy vấn dữ liệu với câu SQL trực tiếp (sync)
        public IEnumerable<T> Query<T>(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.Query<T>(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Truy vấn dữ liệu với câu SQL trực tiếp (async)
        public async Task<IEnumerable<T>> QueryAsync<T>(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.QueryAsync<T>(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Lấy dòng đầu tiên hoặc mặc định với stored procedure (sync)
        public T QueryFirstOrDefaultStoredProcedure<T>(string storedProcedure, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.QueryFirstOrDefault<T>(storedProcedure, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Lấy dòng đầu tiên hoặc mặc định với stored procedure (async)
        public async Task<T> QueryFirstOrDefaultStoredProcedureAsync<T>(string storedProcedure, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.QueryFirstOrDefaultAsync<T>(storedProcedure, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Lấy dòng đầu tiên hoặc mặc định với câu SQL (sync)
        public T QueryFirstOrDefault<T>(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.QueryFirstOrDefault<T>(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Lấy dòng đầu tiên hoặc mặc định với câu SQL (async)
        public async Task<T> QueryFirstOrDefaultAsync<T>(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.QueryFirstOrDefaultAsync<T>(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi câu lệnh SQL không truy vấn với stored procedure (sync)
        public int ExecuteStoredProcedure(string storedProcedure, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.Execute(storedProcedure, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi câu lệnh SQL không truy vấn với stored procedure (async)
        public async Task<int> ExecuteStoredProcedureAsync(string storedProcedureName, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            var result = await connection.QuerySingleAsync<int>(
                storedProcedureName,
                parameters,
                commandType: CommandType.StoredProcedure,
                commandTimeout: DefaultCommandTimeout
            );
            return result;
        }
        
        // Thực thi câu lệnh SQL không truy vấn (sync)
        public int Execute(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.Execute(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi câu lệnh SQL không truy vấn (async)
        public async Task<int> ExecuteAsync(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.ExecuteAsync(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: Thực thi câu lệnh SQL với transaction (sync)
        public int Execute(string sql, object parameters, SqlTransaction transaction)
        {
            return _connection.Execute(sql, parameters, transaction, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: Thực thi câu lệnh SQL với transaction (async)
        public async Task<int> ExecuteAsync(string sql, object parameters, SqlTransaction transaction)
        {
            return await _connection.ExecuteAsync(sql, parameters, transaction, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: Query với transaction (sync)
        public IEnumerable<T> Query<T>(string sql, object parameters, SqlTransaction transaction)
        {
            return _connection.Query<T>(sql, parameters, transaction, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: Query với transaction (async)
        public async Task<IEnumerable<T>> QueryAsync<T>(string sql, object parameters, SqlTransaction transaction)
        {
            return await _connection.QueryAsync<T>(sql, parameters, transaction, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: QueryFirstOrDefault với transaction (sync)
        public T QueryFirstOrDefault<T>(string sql, object parameters, SqlTransaction transaction)
        {
            return _connection.QueryFirstOrDefault<T>(sql, parameters, transaction, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: QueryFirstOrDefault với transaction (async)
        public async Task<T> QueryFirstOrDefaultAsync<T>(string sql, object parameters, SqlTransaction transaction)
        {
            return await _connection.QueryFirstOrDefaultAsync<T>(sql, parameters, transaction, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi câu lệnh SQL và trả về giá trị vô hướng (sync)
        public T ExecuteScalar<T>(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return connection.ExecuteScalar<T>(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi câu lệnh SQL và trả về giá trị vô hướng (async)
        public async Task<T> ExecuteScalarAsync<T>(string sql, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.ExecuteScalarAsync<T>(sql, parameters, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi stored procedure và trả về giá trị vô hướng (async)
        public async Task<T> ExecuteScalarStoredProcedureAsync<T>(string storedProcedure, object parameters = null)
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await connection.ExecuteScalarAsync<T>(storedProcedure, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi multiple queries và trả về nhiều result sets (sync)
        public SqlMapper.GridReader QueryMultiple(string sql, object parameters = null)
        {
            var connection = new SqlConnection(connectionString);
            connection.Open();
            return SqlMapper.QueryMultiple(connection, sql, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // Thực thi multiple queries và trả về nhiều result sets (async)
        public async Task<SqlMapper.GridReader> QueryMultipleAsync(string sql, object parameters = null)
        {
            var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            return await SqlMapper.QueryMultipleAsync(connection, sql, parameters, commandType: CommandType.StoredProcedure, commandTimeout: DefaultCommandTimeout);
        }

        // ← THÊM MỚI: Dispose method để dọn dẹp resources
        public void Dispose()
        {
            _transaction?.Dispose();
            _connection?.Dispose();
        }
    }
}