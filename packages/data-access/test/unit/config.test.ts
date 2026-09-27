import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseDatabaseConfig,
  parseDatabaseUrl,
  redactDatabaseConfig,
  loadDatabaseConfigFromEnv,
} from '../../dist/index.js';

describe('Database Configuration (Pure Unit Tests)', () => {
  it('should parse valid discrete configuration with default pool settings', () => {
    const raw = {
      host: '127.0.0.1',
      port: 5432,
      database: 'shn_db',
      user: 'shn_user',
      password: 'super_secret_password',
      ssl: false,
    };

    const result = parseDatabaseConfig(raw);
    assert.equal(result.isOk, true);
    if (result.isOk) {
      assert.equal(result.value.host, '127.0.0.1');
      assert.equal(result.value.port, 5432);
      assert.equal(result.value.database, 'shn_db');
      assert.equal(result.value.user, 'shn_user');
      assert.equal(result.value.password, 'super_secret_password');
      assert.equal(result.value.ssl, false);
      assert.equal(result.value.maxConnections, 20);
      assert.equal(result.value.minConnections, 2);
      assert.equal(result.value.idleTimeoutMs, 10000);
      assert.equal(result.value.connectionTimeoutMs, 5000);
    }
  });

  it('should parse PostgreSQL connection URLs correctly', () => {
    const url = 'postgresql://admin:vault_pass@db.internal.corp:5433/prod_shn?sslmode=require';
    const parsedResult = parseDatabaseUrl(url);
    assert.equal(parsedResult.isOk, true);
    if (parsedResult.isOk) {
      assert.equal(parsedResult.value.host, 'db.internal.corp');
      assert.equal(parsedResult.value.port, 5433);
      assert.equal(parsedResult.value.database, 'prod_shn');
      assert.equal(parsedResult.value.user, 'admin');
      assert.equal(parsedResult.value.password, 'vault_pass');
      assert.equal(parsedResult.value.ssl, true);
    }
  });

  it('should allow discrete fields to override URL connection parameters', () => {
    const raw = {
      url: 'postgresql://admin:vault_pass@db.internal.corp:5432/base_shn',
      database: 'override_shn',
      maxConnections: 50,
    };

    const result = parseDatabaseConfig(raw);
    assert.equal(result.isOk, true);
    if (result.isOk) {
      assert.equal(result.value.host, 'db.internal.corp');
      assert.equal(result.value.database, 'override_shn');
      assert.equal(result.value.maxConnections, 50);
    }
  });

  it('should redact sensitive credentials and full passwords', () => {
    const configResult = parseDatabaseConfig({
      host: '127.0.0.1',
      port: 5432,
      database: 'shn_db',
      user: 'shn_admin',
      password: 'extremely_sensitive_secret',
    });

    assert.equal(configResult.isOk, true);
    if (configResult.isOk) {
      const redacted = redactDatabaseConfig(configResult.value);
      assert.equal(redacted.hasPassword, true);
      assert.equal('password' in (redacted as unknown as Record<string, unknown>), false);
      assert.equal(JSON.stringify(redacted).includes('extremely_sensitive_secret'), false);
    }
  });

  it('should reject missing or malformed configuration fields fail-closed', () => {
    // Missing host
    const noHost = parseDatabaseConfig({ database: 'db', user: 'u' });
    assert.equal(noHost.isErr, true);

    // Invalid port (out of range)
    const badPort = parseDatabaseConfig({ host: 'localhost', port: 70000, database: 'db', user: 'u' });
    assert.equal(badPort.isErr, true);

    // Missing database
    const noDb = parseDatabaseConfig({ host: 'localhost', port: 5432, user: 'u' });
    assert.equal(noDb.isErr, true);

    // Missing user
    const noUser = parseDatabaseConfig({ host: 'localhost', port: 5432, database: 'db' });
    assert.equal(noUser.isErr, true);

    // maxConnections < minConnections
    const invalidPool = parseDatabaseConfig({
      host: 'localhost',
      port: 5432,
      database: 'db',
      user: 'u',
      maxConnections: 2,
      minConnections: 10,
    });
    assert.equal(invalidPool.isErr, true);
  });

  it('should load database configuration from environment variables with proper precedence', () => {
    const mockEnv: NodeJS.ProcessEnv = {
      SHN_DB_HOST: 'env-host.internal',
      SHN_DB_PORT: '5432',
      SHN_DB_NAME: 'env_shn_db',
      SHN_DB_USER: 'env_user',
      SHN_DB_PASSWORD: 'env_password',
      SHN_DB_MAX_CONNECTIONS: '15',
    };

    const envResult = loadDatabaseConfigFromEnv(mockEnv, 'production');
    assert.equal(envResult.isOk, true);
    if (envResult.isOk) {
      assert.equal(envResult.value.host, 'env-host.internal');
      assert.equal(envResult.value.database, 'env_shn_db');
      assert.equal(envResult.value.user, 'env_user');
      assert.equal(envResult.value.maxConnections, 15);
    }
  });
});
