import { Injectable, Logger } from '@nestjs/common';
import { InjectConnection } from '@nestjs/typeorm';
import { Connection } from 'typeorm';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PostgresService {
  private readonly logger = new Logger(PostgresService.name);

  constructor(
    @InjectConnection('rds')
    private readonly connection: Connection,
    private readonly configService: ConfigService,
  ) {
    this.logger.log('PostgreSQL service initialized');

    // Log connection information (without sensitive data)
    const databaseUrl = this.configService.get<string>('DATABASE_URL');
    if (databaseUrl) {
      // Extract host and database from URL without showing credentials
      try {
        const url = new URL(databaseUrl);
        this.logger.log(
          `Connected to PostgreSQL database at ${url.hostname}/${url.pathname.substring(1)}`,
        );
      } catch (error) {
        this.logger.warn('Invalid DATABASE_URL format');
      }
    } else {
      // Get connection options safely
      const options = this.connection.options as any;
      const host = options.host || 'localhost';
      const database = options.database || 'unknown';
      this.logger.log(
        `Connected to PostgreSQL database at ${host}/${database}`,
      );
    }
  }

  /**
   * Get the database connection
   */
  getConnection(): Connection {
    return this.connection;
  }

  /**
   * Execute a raw SQL query
   */
  async executeQuery(query: string, parameters: any[] = []): Promise<any> {
    const startTime = Date.now();
    try {
      const result = await this.connection.query(query, parameters);
      const duration = Date.now() - startTime;

      // Log query performance for slow queries
      if (duration > 1000) {
        this.logger.warn(`Slow query detected (${duration}ms): ${query}`);
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Query error: ${error.message}`, error.stack);
      throw new Error(`Failed to execute query: ${error.message}`);
    }
  }

  /**
   * Check database connection health
   */
  async checkHealth(): Promise<boolean> {
    try {
      await this.connection.query('SELECT 1');
      return true;
    } catch (error: any) {
      this.logger.error(`Health check failed: ${error.message}`, error.stack);
      return false;
    }
  }

  /**
   * Get RDS instance information
   */
  async getRdsInstanceInfo(): Promise<any> {
    try {
      // Get PostgreSQL version
      const versionResult = await this.connection.query('SELECT version()');

      // Get RDS specific information
      const rdsInfoQuery = `
        SELECT 
          current_database() as db_name,
          current_setting('server_version') as pg_version,
          pg_size_pretty(pg_database_size(current_database())) as db_size,
          current_setting('max_connections') as max_connections,
          (SELECT count(*) FROM pg_stat_activity) as active_connections,
          current_setting('shared_buffers') as shared_buffers,
          current_setting('work_mem') as work_mem,
          current_setting('maintenance_work_mem') as maintenance_work_mem,
          current_setting('effective_cache_size') as effective_cache_size
      `;

      const rdsInfo = await this.connection.query(rdsInfoQuery);

      // Get connection options safely
      const options = this.connection.options as any;

      return {
        version: versionResult[0].version,
        instanceInfo: rdsInfo[0],
        connectionInfo: {
          usingDatabaseUrl: !!this.configService.get<string>('DATABASE_URL'),
          host: options.host || 'from-connection-string',
          database: options.database || 'from-connection-string',
        },
      };
    } catch (error: any) {
      this.logger.error(
        `Failed to get RDS info: ${error.message}`,
        error.stack,
      );
      throw new Error(
        `Failed to get RDS instance information: ${error.message}`,
      );
    }
  }

  /**
   * Get database statistics
   */
  async getDatabaseStats(): Promise<any> {
    try {
      const dbSize = await this.connection.query(`
        SELECT pg_size_pretty(pg_database_size(current_database())) as db_size
      `);

      const tableStats = await this.connection.query(`
        SELECT 
          relname as table_name,
          n_live_tup as row_count,
          pg_size_pretty(pg_total_relation_size(relid)) as total_size
        FROM pg_stat_user_tables
        ORDER BY n_live_tup DESC
      `);

      const indexStats = await this.connection.query(`
        SELECT
          indexrelname as index_name,
          relname as table_name,
          idx_scan as index_scans,
          pg_size_pretty(pg_relation_size(indexrelid)) as index_size
        FROM pg_stat_user_indexes
        ORDER BY idx_scan DESC
      `);

      const connectionStats = await this.connection.query(`
        SELECT 
          state, 
          count(*) as count
        FROM pg_stat_activity 
        GROUP BY state
      `);

      return {
        databaseSize: dbSize[0].db_size,
        tables: tableStats,
        indexes: indexStats,
        connections: connectionStats,
      };
    } catch (error: any) {
      this.logger.error(
        `Failed to get DB stats: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to get database statistics: ${error.message}`);
    }
  }

  /**
   * Monitor slow queries
   */
  async getSlowQueries(): Promise<any> {
    try {
      // This requires pg_stat_statements extension to be enabled
      const slowQueriesQuery = `
        SELECT 
          query,
          calls,
          total_time / calls as avg_time,
          min_time,
          max_time,
          mean_time,
          stddev_time,
          rows
        FROM pg_stat_statements
        ORDER BY total_time / calls DESC
        LIMIT 10
      `;

      try {
        const slowQueries = await this.connection.query(slowQueriesQuery);
        return slowQueries;
      } catch (error) {
        // pg_stat_statements might not be available
        this.logger.warn('pg_stat_statements extension not available');

        // Fallback to pg_stat_activity for active queries
        const activeQueriesQuery = `
          SELECT 
            pid,
            usename as username,
            application_name,
            client_addr,
            state,
            query_start,
            NOW() - query_start as duration,
            query
          FROM pg_stat_activity
          WHERE state = 'active' AND query != '<IDLE>' AND query NOT ILIKE '%pg_stat_activity%'
          ORDER BY duration DESC
        `;

        return await this.connection.query(activeQueriesQuery);
      }
    } catch (error: any) {
      this.logger.error(
        `Failed to get slow queries: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to monitor slow queries: ${error.message}`);
    }
  }

  /**
   * Get connection pool statistics
   */
  async getConnectionPoolStats(): Promise<any> {
    try {
      const poolStats = {
        total: 0,
        idle: 0,
        active: 0,
      };

      // Get connection stats from pg_stat_activity
      const connectionStats = await this.connection.query(`
        SELECT 
          state, 
          count(*) as count
        FROM pg_stat_activity 
        GROUP BY state
      `);

      connectionStats.forEach((stat) => {
        poolStats.total += parseInt(stat.count);
        if (stat.state === 'active') {
          poolStats.active += parseInt(stat.count);
        } else if (stat.state === 'idle') {
          poolStats.idle += parseInt(stat.count);
        }
      });

      return poolStats;
    } catch (error: any) {
      this.logger.error(
        `Failed to get pool stats: ${error.message}`,
        error.stack,
      );
      throw new Error(
        `Failed to get connection pool statistics: ${error.message}`,
      );
    }
  }
}
