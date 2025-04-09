import { DatabaseConnectionEntity } from '../database/entities/database-connection.entity';

export function generateConnectionStringWithDate(
  connection: DatabaseConnectionEntity,
  includeDate: boolean = true,
): string | null {
  const {
    type,
    host,
    port,
    username,
    password,
    databaseName,
    connectionString,
  } = connection;

  if (connectionString) {
    return includeDate
      ? `${connectionString}${connectionString.includes('?') ? '&' : '?'}generatedAt=${new Date().toISOString()}`
      : connectionString;
  }

  switch (type) {
    case 'mongodb':
      if (host && databaseName) {
        const auth = username && password ? `${username}:${password}@` : '';
        return includeDate
          ? `mongodb://${auth}${host}:${port}/${databaseName}?generatedAt=${new Date().toISOString()}`
          : `mongodb://${auth}${host}:${port}/${databaseName}`;
      }
      return null;
    case 'mysql':
      if (host && port && username && password && databaseName) {
        return includeDate
          ? `mysql://${username}:${password}@${host}:${port}/${databaseName}?generatedAt=${new Date().toISOString()}`
          : `mysql://${username}:${password}@${host}:${port}/${databaseName}`;
      }
      return null;
    case 'postgresql':
      if (host && port && username && password && databaseName) {
        return includeDate
          ? `postgresql://${username}:${password}@${host}:${port}/${databaseName}?generatedAt=${new Date().toISOString()}`
          : `postgresql://${username}:${password}@${host}:${port}/${databaseName}`;
      }
      return null;
    case 'sqlite':
      if (databaseName) {
        return includeDate
          ? `sqlite:${databaseName}?generatedAt=${new Date().toISOString()}`
          : `sqlite:${databaseName}`;
      }
      return null;
    default:
      return null;
  }
}

export function extractConnectionDetails(
  connectionString: string,
  typeHint?: DatabaseConnectionEntity['type'],
): Partial<DatabaseConnectionEntity> {
  const details: Partial<DatabaseConnectionEntity> = {};

  if (!connectionString) {
    return details;
  }

  const lowerCaseConnectionString = connectionString.toLowerCase();
  if (lowerCaseConnectionString.startsWith('mongodb://')) {
    details.type = 'mongodb';
    const uriParts = lowerCaseConnectionString
      .substring('mongodb://'.length)
      .split('/');
    if (uriParts.length > 0) {
      const hostPortAuth = uriParts[0];
      const authParts = hostPortAuth.split('@');
      let hostPort = authParts.length > 1 ? authParts[1] : hostPortAuth;
      const credentials = authParts.length > 1 ? authParts[0] : '';
      const hostPortParts = hostPort.split(':');
      details.host = hostPortParts[0];
      if (hostPortParts.length > 1) {
        details.port = parseInt(hostPortParts[1], 10);
      }
      if (credentials) {
        const credParts = credentials.split(':');
        details.username = credParts[0];
        details.password = credParts.length > 1 ? credParts[1] : undefined;
      }
      if (uriParts.length > 1) {
        details.databaseName = uriParts[1].split('?')[0];
      }
      details.connectionString = connectionString;
    }
  } else if (lowerCaseConnectionString.startsWith('mysql://')) {
    details.type = 'mysql';
    const uriParts = lowerCaseConnectionString
      .substring('mysql://'.length)
      .split('@');
    if (uriParts.length === 2) {
      const authHostPort = uriParts[0];
      const dbHostPort = uriParts[1].split('/');
      const credentialsParts = authHostPort.split(':');
      details.username = credentialsParts[0];
      details.password =
        credentialsParts.length > 1 ? credentialsParts[1] : undefined;
      const hostPortParts = dbHostPort[0].split(':');
      details.host = hostPortParts[0];
      if (hostPortParts.length > 1) {
        details.port = parseInt(hostPortParts[1], 10);
      }
      if (dbHostPort.length > 1) {
        details.databaseName = dbHostPort[1].split('?')[0];
      }
      details.connectionString = connectionString;
    }
  } else if (
    lowerCaseConnectionString.startsWith('postgresql://') ||
    lowerCaseConnectionString.startsWith('postgres://')
  ) {
    details.type = 'postgresql';
    const protocolLength = lowerCaseConnectionString.startsWith('postgresql://')
      ? 'postgresql://'.length
      : 'postgres://'.length;

    const uriParts = lowerCaseConnectionString
      .substring(protocolLength)
      .split('@');

    if (uriParts.length === 2) {
      const credentialsHostPort = uriParts[0];
      const dbHostPort = uriParts[1].split('/');
      const credentialsParts = credentialsHostPort.split(':');
      details.username = credentialsParts[0];
      details.password =
        credentialsParts.length > 1 ? credentialsParts[1] : undefined;
      const hostPortParts = dbHostPort[0].split(':');
      details.host = hostPortParts[0];
      if (hostPortParts.length > 1) {
        details.port = parseInt(hostPortParts[1], 10);
      }
      if (dbHostPort.length > 1) {
        details.databaseName = dbHostPort[1].split('?')[0];
      }
      details.connectionString = connectionString;
    }
  } else if (lowerCaseConnectionString.startsWith('sqlite:')) {
    details.type = 'sqlite';
    details.databaseName = lowerCaseConnectionString
      .substring('sqlite:'.length)
      .split('?')[0];
    details.connectionString = connectionString;
  } else if (typeHint === 'dynamodb') {
    details.type = 'dynamodb';
    details.connectionString = connectionString;
    // For DynamoDB, the connection string might be more about region and credentials,
    // which are often handled by SDK configuration rather than a single URL.
    // You might need more specific parsing logic here if your connection string format is custom.
  } else {
    // Could not determine the type from the connection string
    if (typeHint) {
      details.type = typeHint;
      details.connectionString = connectionString;
      // If you have a type hint, you might want to handle specific parsing for that type
      // even if the connection string doesn't have a clear prefix.
    }
  }

  // Ensure type is set if typeHint was provided and no other type was inferred
  if (!details.type && typeHint) {
    details.type = typeHint;
  }

  return details;
}
