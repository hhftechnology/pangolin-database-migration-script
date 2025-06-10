#!/bin/bash

# Pangolin SQLite to PostgreSQL Migration Script
# This script migrates the Pangolin database from SQLite to PostgreSQL

set -e # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths
DEFAULT_SQLITE_PATH="./config/db/db.sqlite"
DEFAULT_CONFIG_PATH="./config/config.yml"

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to prompt for user input with default value
prompt_with_default() {
    local prompt=$1
    local default=$2
    local var_name=$3

    read -p "$prompt [$default]: " user_input
    if [ -z "$user_input" ]; then
        eval "$var_name='$default'"
    else
        eval "$var_name='$user_input'"
    fi
}

# Function to validate file exists
validate_file() {
    local file_path=$1
    local file_type=$2

    if [ ! -f "$file_path" ]; then
        print_message $RED "Error: $file_type not found at: $file_path"
        return 1
    fi
    return 0
}

# Function to backup files
backup_file() {
    local file_path=$1
    local backup_path="${file_path}.backup.$(date +%Y%m%d_%H%M%S)"

    if [ -f "$file_path" ]; then
        cp "$file_path" "$backup_path"
        print_message $GREEN "Backed up $file_path to $backup_path"
    fi
}

# Function to check PostgreSQL connection
check_postgres_connection() {
    local pg_host=$1
    local pg_port=$2
    local pg_user=$3
    local pg_pass=$4
    local pg_db=$5

    PGPASSWORD="$pg_pass" psql -h "$pg_host" -p "$pg_port" -U "$pg_user" -d postgres -c "SELECT 1;" >/dev/null 2>&1
    return $?
}

# Function to create PostgreSQL database structure
create_postgres_structure() {
    local pg_host=$1
    local pg_port=$2
    local pg_user=$3
    local pg_pass=$4
    local pg_db=$5

    print_message $BLUE "Creating PostgreSQL database structure..."

    # Create database if it doesn't exist
    PGPASSWORD="$pg_pass" psql -h "$pg_host" -p "$pg_port" -U "$pg_user" -d postgres -c "CREATE DATABASE $PG_DB;" 2>/dev/null || true

    # Create Pangolin tables based on the actual schema
    PGPASSWORD="$pg_pass" psql -h "$pg_host" -p "$pg_port" -U "$pg_user" -d "$pg_db" <<'EOF'
-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Domains table
CREATE TABLE IF NOT EXISTS domains (
    "domainId" TEXT PRIMARY KEY,
    "baseDomain" TEXT NOT NULL,
    "configManaged" BOOLEAN NOT NULL DEFAULT FALSE
);

-- Organizations table
CREATE TABLE IF NOT EXISTS orgs (
    "orgId" TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

-- Organization domains table
CREATE TABLE IF NOT EXISTS "orgDomains" (
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    "domainId" TEXT NOT NULL REFERENCES domains("domainId") ON DELETE CASCADE
);

-- Exit nodes table
CREATE TABLE IF NOT EXISTS "exitNodes" (
    "exitNodeId" SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "listenPort" INTEGER NOT NULL,
    "reachableAt" TEXT
);

-- Sites table
CREATE TABLE IF NOT EXISTS sites (
    "siteId" SERIAL PRIMARY KEY,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    "niceId" TEXT NOT NULL,
    "exitNodeId" INTEGER REFERENCES "exitNodes"("exitNodeId") ON DELETE SET NULL,
    name TEXT NOT NULL,
    "pubKey" TEXT,
    subnet TEXT NOT NULL,
    "megabytesIn" INTEGER,
    "megabytesOut" INTEGER,
    "lastBandwidthUpdate" TEXT,
    type TEXT NOT NULL,
    online BOOLEAN NOT NULL DEFAULT FALSE,
    "dockerSocketEnabled" BOOLEAN NOT NULL DEFAULT TRUE
);

-- Resources table
CREATE TABLE IF NOT EXISTS resources (
    "resourceId" SERIAL PRIMARY KEY,
    "siteId" INTEGER NOT NULL REFERENCES sites("siteId") ON DELETE CASCADE,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    name TEXT NOT NULL,
    subdomain TEXT,
    "fullDomain" TEXT,
    "domainId" TEXT REFERENCES domains("domainId") ON DELETE SET NULL,
    ssl BOOLEAN NOT NULL DEFAULT FALSE,
    "blockAccess" BOOLEAN NOT NULL DEFAULT FALSE,
    sso BOOLEAN NOT NULL DEFAULT TRUE,
    http BOOLEAN NOT NULL DEFAULT TRUE,
    protocol TEXT NOT NULL,
    "proxyPort" INTEGER,
    "emailWhitelistEnabled" BOOLEAN NOT NULL DEFAULT FALSE,
    "isBaseDomain" BOOLEAN,
    "applyRules" BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    "stickySession" BOOLEAN NOT NULL DEFAULT FALSE,
    "tlsServerName" TEXT,
    "setHostHeader" TEXT
);

-- Targets table
CREATE TABLE IF NOT EXISTS targets (
    "targetId" SERIAL PRIMARY KEY,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    ip TEXT NOT NULL,
    method TEXT,
    port INTEGER NOT NULL,
    "internalPort" INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

-- Identity providers table
CREATE TABLE IF NOT EXISTS idp (
    "idpId" SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    "defaultRoleMapping" TEXT,
    "defaultOrgMapping" TEXT,
    "autoProvision" BOOLEAN NOT NULL DEFAULT FALSE
);

-- Users table
CREATE TABLE IF NOT EXISTS "user" (
    id TEXT PRIMARY KEY,
    email TEXT,
    username TEXT NOT NULL,
    name TEXT,
    type TEXT NOT NULL,
    "idpId" INTEGER REFERENCES idp("idpId") ON DELETE CASCADE,
    "passwordHash" TEXT,
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT FALSE,
    "twoFactorSecret" TEXT,
    "emailVerified" BOOLEAN NOT NULL DEFAULT FALSE,
    "dateCreated" TEXT NOT NULL,
    "serverAdmin" BOOLEAN NOT NULL DEFAULT FALSE
);

-- Newt table
CREATE TABLE IF NOT EXISTS newt (
    id TEXT PRIMARY KEY,
    "secretHash" TEXT NOT NULL,
    "dateCreated" TEXT NOT NULL,
    "siteId" INTEGER REFERENCES sites("siteId") ON DELETE CASCADE
);

-- Two factor backup codes table
CREATE TABLE IF NOT EXISTS "twoFactorBackupCodes" (
    id SERIAL PRIMARY KEY,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "codeHash" TEXT NOT NULL
);

-- Sessions table
CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "expiresAt" INTEGER NOT NULL
);

-- Newt sessions table
CREATE TABLE IF NOT EXISTS "newtSession" (
    id TEXT PRIMARY KEY,
    "newtId" TEXT NOT NULL REFERENCES newt(id) ON DELETE CASCADE,
    "expiresAt" INTEGER NOT NULL
);

-- User organizations table
CREATE TABLE IF NOT EXISTS "userOrgs" (
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    "roleId" INTEGER NOT NULL,
    "isOwner" BOOLEAN NOT NULL DEFAULT FALSE
);

-- Email verification codes table
CREATE TABLE IF NOT EXISTS "emailVerificationCodes" (
    id SERIAL PRIMARY KEY,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    "expiresAt" INTEGER NOT NULL
);

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS "passwordResetTokens" (
    id SERIAL PRIMARY KEY,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" INTEGER NOT NULL
);

-- Actions table
CREATE TABLE IF NOT EXISTS actions (
    "actionId" TEXT PRIMARY KEY,
    name TEXT,
    description TEXT
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    "roleId" SERIAL PRIMARY KEY,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    "isAdmin" BOOLEAN,
    name TEXT NOT NULL,
    description TEXT
);

-- Add foreign key constraint to userOrgs after roles table is created
ALTER TABLE "userOrgs" ADD CONSTRAINT "userOrgs_roleId_fkey" 
    FOREIGN KEY ("roleId") REFERENCES roles("roleId") ON DELETE RESTRICT;

-- Role actions table
CREATE TABLE IF NOT EXISTS "roleActions" (
    "roleId" INTEGER NOT NULL REFERENCES roles("roleId") ON DELETE CASCADE,
    "actionId" TEXT NOT NULL REFERENCES actions("actionId") ON DELETE CASCADE,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE
);

-- User actions table
CREATE TABLE IF NOT EXISTS "userActions" (
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "actionId" TEXT NOT NULL REFERENCES actions("actionId") ON DELETE CASCADE,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE
);

-- Role sites table
CREATE TABLE IF NOT EXISTS "roleSites" (
    "roleId" INTEGER NOT NULL REFERENCES roles("roleId") ON DELETE CASCADE,
    "siteId" INTEGER NOT NULL REFERENCES sites("siteId") ON DELETE CASCADE
);

-- User sites table
CREATE TABLE IF NOT EXISTS "userSites" (
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "siteId" INTEGER NOT NULL REFERENCES sites("siteId") ON DELETE CASCADE
);

-- Role resources table
CREATE TABLE IF NOT EXISTS "roleResources" (
    "roleId" INTEGER NOT NULL REFERENCES roles("roleId") ON DELETE CASCADE,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE
);

-- User resources table
CREATE TABLE IF NOT EXISTS "userResources" (
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE
);

-- Limits table
CREATE TABLE IF NOT EXISTS limits (
    "limitId" SERIAL PRIMARY KEY,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    name TEXT NOT NULL,
    value INTEGER NOT NULL,
    description TEXT
);

-- User invites table
CREATE TABLE IF NOT EXISTS "userInvites" (
    "inviteId" TEXT PRIMARY KEY,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    email TEXT NOT NULL,
    "expiresAt" INTEGER NOT NULL,
    token TEXT NOT NULL,
    "roleId" INTEGER NOT NULL REFERENCES roles("roleId") ON DELETE CASCADE
);

-- Resource pincode table
CREATE TABLE IF NOT EXISTS "resourcePincode" (
    "pincodeId" SERIAL PRIMARY KEY,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    "pincodeHash" TEXT NOT NULL,
    "digitLength" INTEGER NOT NULL
);

-- Resource password table
CREATE TABLE IF NOT EXISTS "resourcePassword" (
    "passwordId" SERIAL PRIMARY KEY,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    "passwordHash" TEXT NOT NULL
);

-- Resource access token table
CREATE TABLE IF NOT EXISTS "resourceAccessToken" (
    "accessTokenId" TEXT PRIMARY KEY,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    "tokenHash" TEXT NOT NULL,
    "sessionLength" INTEGER NOT NULL,
    "expiresAt" INTEGER,
    title TEXT,
    description TEXT,
    "createdAt" INTEGER NOT NULL
);

-- Resource whitelist table
CREATE TABLE IF NOT EXISTS "resourceWhitelist" (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE
);

-- Resource sessions table
CREATE TABLE IF NOT EXISTS "resourceSessions" (
    id TEXT PRIMARY KEY,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    "expiresAt" INTEGER NOT NULL,
    "sessionLength" INTEGER NOT NULL,
    "doNotExtend" BOOLEAN NOT NULL DEFAULT FALSE,
    "isRequestToken" BOOLEAN,
    "userSessionId" TEXT REFERENCES session(id) ON DELETE CASCADE,
    "passwordId" INTEGER REFERENCES "resourcePassword"("passwordId") ON DELETE CASCADE,
    "pincodeId" INTEGER REFERENCES "resourcePincode"("pincodeId") ON DELETE CASCADE,
    "whitelistId" INTEGER REFERENCES "resourceWhitelist"(id) ON DELETE CASCADE,
    "accessTokenId" TEXT REFERENCES "resourceAccessToken"("accessTokenId") ON DELETE CASCADE
);

-- Resource OTP table
CREATE TABLE IF NOT EXISTS "resourceOtp" (
    "otpId" SERIAL PRIMARY KEY,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    email TEXT NOT NULL,
    "otpHash" TEXT NOT NULL,
    "expiresAt" INTEGER NOT NULL
);

-- Version migrations table
CREATE TABLE IF NOT EXISTS "versionMigrations" (
    version TEXT PRIMARY KEY,
    "executedAt" INTEGER NOT NULL
);

-- Resource rules table
CREATE TABLE IF NOT EXISTS "resourceRules" (
    "ruleId" SERIAL PRIMARY KEY,
    "resourceId" INTEGER NOT NULL REFERENCES resources("resourceId") ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL,
    action TEXT NOT NULL,
    match TEXT NOT NULL,
    value TEXT NOT NULL
);

-- Supporter key table
CREATE TABLE IF NOT EXISTS "supporterKey" (
    "keyId" SERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    "githubUsername" TEXT NOT NULL,
    phrase TEXT,
    tier TEXT,
    valid BOOLEAN NOT NULL DEFAULT FALSE
);

-- IDP OIDC config table
CREATE TABLE IF NOT EXISTS "idpOidcConfig" (
    "idpOauthConfigId" SERIAL PRIMARY KEY,
    "idpId" INTEGER NOT NULL REFERENCES idp("idpId") ON DELETE CASCADE,
    "clientId" TEXT NOT NULL,
    "clientSecret" TEXT NOT NULL,
    "authUrl" TEXT NOT NULL,
    "tokenUrl" TEXT NOT NULL,
    "identifierPath" TEXT NOT NULL,
    "emailPath" TEXT,
    "namePath" TEXT,
    scopes TEXT NOT NULL
);

-- License key table
CREATE TABLE IF NOT EXISTS "licenseKey" (
    "licenseKeyId" TEXT PRIMARY KEY NOT NULL,
    "instanceId" TEXT NOT NULL,
    token TEXT NOT NULL
);

-- Host meta table
CREATE TABLE IF NOT EXISTS "hostMeta" (
    "hostMetaId" TEXT PRIMARY KEY NOT NULL,
    "createdAt" INTEGER NOT NULL
);

-- API keys table
CREATE TABLE IF NOT EXISTS "apiKeys" (
    "apiKeyId" TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    "apiKeyHash" TEXT NOT NULL,
    "lastChars" TEXT NOT NULL,
    "dateCreated" TEXT NOT NULL,
    "isRoot" BOOLEAN NOT NULL DEFAULT FALSE
);

-- API key actions table
CREATE TABLE IF NOT EXISTS "apiKeyActions" (
    "apiKeyId" TEXT NOT NULL REFERENCES "apiKeys"("apiKeyId") ON DELETE CASCADE,
    "actionId" TEXT NOT NULL REFERENCES actions("actionId") ON DELETE CASCADE
);

-- API key org table
CREATE TABLE IF NOT EXISTS "apiKeyOrg" (
    "apiKeyId" TEXT NOT NULL REFERENCES "apiKeys"("apiKeyId") ON DELETE CASCADE,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE
);

-- IDP org table
CREATE TABLE IF NOT EXISTS "idpOrg" (
    "idpId" INTEGER NOT NULL REFERENCES idp("idpId") ON DELETE CASCADE,
    "orgId" TEXT NOT NULL REFERENCES orgs("orgId") ON DELETE CASCADE,
    "roleMapping" TEXT,
    "orgMapping" TEXT
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sites_org_id ON sites("orgId");
CREATE INDEX IF NOT EXISTS idx_resources_site_id ON resources("siteId");
CREATE INDEX IF NOT EXISTS idx_resources_org_id ON resources("orgId");
CREATE INDEX IF NOT EXISTS idx_targets_resource_id ON targets("resourceId");
CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON session("userId");
CREATE INDEX IF NOT EXISTS idx_newt_site_id ON newt("siteId");
CREATE INDEX IF NOT EXISTS idx_user_orgs_user_id ON "userOrgs"("userId");
CREATE INDEX IF NOT EXISTS idx_user_orgs_org_id ON "userOrgs"("orgId");
EOF

    print_message $GREEN "PostgreSQL database structure created"
}

# Function to migrate data from SQLite to PostgreSQL
migrate_data() {
    local sqlite_path=$1
    local pg_host=$2
    local pg_port=$3
    local pg_user=$4
    local pg_pass=$5
    local pg_db=$6

    print_message $BLUE "Migrating data from SQLite to PostgreSQL..."

    # Create temporary directory for migration
    TEMP_DIR=$(mktemp -d)

    # List of tables in correct order (respecting foreign key constraints)
    TABLES=(
        "domains"
        "orgs"
        "orgDomains"
        "exitNodes"
        "sites"
        "resources"
        "targets"
        "idp"
        "user"
        "newt"
        "twoFactorBackupCodes"
        "session"
        "newtSession"
        "actions"
        "roles"
        "userOrgs"
        "emailVerificationCodes"
        "passwordResetTokens"
        "roleActions"
        "userActions"
        "roleSites"
        "userSites"
        "roleResources"
        "userResources"
        "limits"
        "userInvites"
        "resourcePincode"
        "resourcePassword"
        "resourceAccessToken"
        "resourceWhitelist"
        "resourceSessions"
        "resourceOtp"
        "versionMigrations"
        "resourceRules"
        "supporterKey"
        "idpOidcConfig"
        "licenseKey"
        "hostMeta"
        "apiKeys"
        "apiKeyActions"
        "apiKeyOrg"
        "idpOrg"
    )

    # Export each table from SQLite
    for table in "${TABLES[@]}"; do
        # Check if the table exists in the source SQLite database
        table_exists_in_sqlite=$(sqlite3 "$sqlite_path" "SELECT name FROM sqlite_master WHERE type='table' AND name='$table';")

        if [ -z "$table_exists_in_sqlite" ]; then
            print_message $YELLOW "Table '$table' not found in SQLite database, skipping."
            continue
        fi

        print_message $BLUE "Exporting table: $table"

        # Export to CSV with proper escaping
        sqlite3 -header -csv "$sqlite_path" "SELECT * FROM \"$table\";" > "$TEMP_DIR/${table}.csv"

        # Check if table has data to import
        if [ -s "$TEMP_DIR/${table}.csv" ] && [ $(wc -l < "$TEMP_DIR/${table}.csv") -gt 1 ]; then
            # Truncate the table in PostgreSQL before importing to prevent duplicate key errors
            print_message $BLUE "Clearing existing data from PostgreSQL table: $table"
            PGPASSWORD="$pg_pass" psql -h "$pg_host" -p "$pg_port" -U "$pg_user" -d "$pg_db" -c "TRUNCATE TABLE \"$table\" RESTART IDENTITY CASCADE;"

            # Import to PostgreSQL
            PGPASSWORD="$pg_pass" psql -h "$pg_host" -p "$pg_port" -U "$pg_user" -d "$pg_db" -c "\COPY \"$table\" FROM '$TEMP_DIR/${table}.csv' WITH CSV HEADER;"

            # Reset sequences for tables with SERIAL columns
            case "$table" in
                "sites"|"resources"|"targets"|"exitNodes"|"twoFactorBackupCodes"|"emailVerificationCodes"|"passwordResetTokens"|"roles"|"limits"|"resourcePincode"|"resourcePassword"|"resourceWhitelist"|"resourceOtp"|"resourceRules"|"supporterKey"|"idpOidcConfig"|"idp")
                    # Get the primary key column name from the PRAGMA info, removing any quotes
                    pk_col=$(sqlite3 "$sqlite_path" "PRAGMA table_info(\"$table\");" | grep -E '\|1$' | cut -d'|' -f2 | tr -d '"')
                    if [ ! -z "$pk_col" ]; then
                        # This command resets the sequence for serial columns after data import.
                        # We wrap it to prevent script exit on error, as some tables in the list might not have a sequence.
                        (
                            set +e # Temporarily disable exit on error for this command
                            PGPASSWORD="$pg_pass" psql -h "$pg_host" -p "$pg_port" -U "$pg_user" -d "$pg_db" -c "SELECT setval(pg_get_serial_sequence('$table', '$pk_col'), COALESCE(MAX(\"$pk_col\"), 0), true) FROM \"$table\";"
                            if [ $? -ne 0 ]; then
                                print_message $YELLOW "Notice: Could not update sequence for table '$table'. This is usually safe to ignore if the table is not using a sequence."
                            fi
                        )
                    fi
                    ;;
            esac
        else
            print_message $YELLOW "Table $table is empty or contains no data, skipping import..."
        fi
    done

    # Cleanup
    rm -rf "$TEMP_DIR"

    print_message $GREEN "Data migration completed"
}

# Function to update config.yml for PostgreSQL
update_config_yml() {
    local config_path=$1
    local pg_host=$2
    local pg_port=$3
    local pg_user=$4
    local pg_pass=$5
    local pg_db=$6
    
    print_message $BLUE "Updating config.yml for PostgreSQL..."
    
    # Create a backup of the original config
    cp "$config_path" "${config_path}.pre-postgres"
    
    # Check if the postgres key already exists in the config file
    if grep -q "^postgres:" "$config_path"; then
        # If it exists, replace the connection_string
        sed -i "s|^\(\s*connection_string:\s*\).*|\1postgresql://$pg_user:$pg_pass@$pg_host:$pg_port/$pg_db|" "$config_path"
    else
        # If it doesn't exist, append the new configuration
        cat >> "$config_path" <<EOF

# PostgreSQL Database Configuration (Added by migration script)
postgres:
    connection_string: postgresql://$pg_user:$pg_pass@$pg_host:$pg_port/$pg_db
EOF
    fi
    
    print_message $GREEN "config.yml updated with PostgreSQL settings"
}


# Function to generate docker-compose PostgreSQL service
generate_postgres_docker_compose() {
    local pg_user=$1
    local pg_pass=$2
    local pg_db=$3

    print_message $BLUE "\nGenerating PostgreSQL docker-compose configuration..."

    cat > "docker-compose.postgres.yml" <<EOF
# PostgreSQL service configuration for Pangolin
# Add this to your existing docker-compose.yml or use with docker-compose -f

services:
  postgres:
    image: postgres:17
    container_name: postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: $pg_user
      POSTGRES_PASSWORD: $pg_pass
      POSTGRES_DB: $pg_db
    volumes:
      - ./config/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $pg_user"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - pangolin

  # Update your Pangolin service to use PostgreSQL
  pangolin:
    image: fosrl/pangolin:postgresql-latest
    container_name: pangolin
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./config:/app/config
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/api/v1/"]
      interval: "10s"
      timeout: "10s"
      retries: 15
    networks:
      - pangolin

networks:
  pangolin:
    external: true
EOF

    print_message $GREEN "PostgreSQL docker-compose configuration saved to: docker-compose.postgres.yml"
}

# Main migration function
main() {
    print_message $BLUE "=== Pangolin SQLite to PostgreSQL Migration Script ==="

    # Check required commands
    if ! command_exists sqlite3; then
        print_message $RED "Error: sqlite3 is not installed. Please install it first."
        print_message $YELLOW "On Ubuntu/Debian: sudo apt-get install sqlite3"
        print_message $YELLOW "On RHEL/CentOS: sudo yum install sqlite"
        exit 1
    fi

    if ! command_exists psql; then
        print_message $RED "Error: PostgreSQL client (psql) is not installed. Please install it first."
        print_message $YELLOW "On Ubuntu/Debian: sudo apt-get install postgresql-client"
        print_message $YELLOW "On RHEL/CentOS: sudo yum install postgresql"
        exit 1
    fi

    # Get user inputs
    print_message $YELLOW "\nStep 1: SQLite Database Configuration"
    prompt_with_default "Enter SQLite database path" "$DEFAULT_SQLITE_PATH" SQLITE_PATH
    prompt_with_default "Enter Pangolin config.yml path" "$DEFAULT_CONFIG_PATH" CONFIG_PATH

    # Validate SQLite database exists
    if ! validate_file "$SQLITE_PATH" "SQLite database"; then
        exit 1
    fi

    # Validate config.yml exists
    if ! validate_file "$CONFIG_PATH" "config.yml"; then
        exit 1
    fi

    print_message $RED "\nIMPORTANT: Your PostgreSQL database must be running and accessible BEFORE proceeding."
    print_message $YELLOW "\nStep 2: PostgreSQL Database Configuration"
    prompt_with_default "Enter PostgreSQL host" "localhost-ip-or-container-name" PG_HOST
    prompt_with_default "Enter PostgreSQL port" "5432" PG_PORT
    prompt_with_default "Enter PostgreSQL username" "postgres" PG_USER

    # Password input (hidden)
    read -s -p "Enter PostgreSQL password: " PG_PASS
    echo

    prompt_with_default "Enter PostgreSQL database name" "postgres" PG_DB

    # Test PostgreSQL connection
    print_message $BLUE "\nTesting PostgreSQL connection..."
    if ! check_postgres_connection "$PG_HOST" "$PG_PORT" "$PG_USER" "$PG_PASS" "postgres"; then
        print_message $RED "Error: Cannot connect to PostgreSQL. Please check your credentials and ensure the database is running."
        exit 1
    fi
    print_message $GREEN "PostgreSQL connection successful"

    # Check if database exists, create if not
    DB_EXISTS=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'")
    if [ "$DB_EXISTS" != "1" ]; then
        print_message $YELLOW "Database $PG_DB does not exist. Creating..."
        PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres -c "CREATE DATABASE $PG_DB;"
        print_message $GREEN "Database created"
    fi

    # Confirmation
    print_message $YELLOW "\nMigration Summary:"
    echo "Source SQLite: $SQLITE_PATH"
    echo "Target PostgreSQL: $PG_USER@$PG_HOST:$PG_PORT/$PG_DB"
    echo "Config file: $CONFIG_PATH"

    read -p "Do you want to proceed with the migration? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_message $YELLOW "Migration cancelled"
        exit 0
    fi

    # Create backups
    print_message $BLUE "\nCreating backups..."
    backup_file "$SQLITE_PATH"
    backup_file "$CONFIG_PATH"

    # Create PostgreSQL structure
    create_postgres_structure "$PG_HOST" "$PG_PORT" "$PG_USER" "$PG_PASS" "$PG_DB"

    # Migrate data
    migrate_data "$SQLITE_PATH" "$PG_HOST" "$PG_PORT" "$PG_USER" "$PG_PASS" "$PG_DB"

    # Update config.yml
    update_config_yml "$CONFIG_PATH" "$PG_HOST" "$PG_PORT" "$PG_USER" "$PG_PASS" "$PG_DB"

    # Generate docker-compose configuration if using Docker
    read -p "Do you want to generate a docker-compose configuration for PostgreSQL? (y/N): " gen_compose
    if [[ "$gen_compose" =~ ^[Yy]$ ]]; then
        generate_postgres_docker_compose "$PG_USER" "$PG_PASS" "$PG_DB"
    fi

    print_message $GREEN "\n=== Migration completed successfully! ==="
    print_message $YELLOW "\nNext steps:"
    echo "1. Update your Pangolin service in docker-compose.yml to use the PostgreSQL-enabled image:"
    print_message $BLUE "   image: fosrl/pangolin:postgresql-latest"
    echo ""
    echo "2. Ensure your Pangolin service depends_on the postgres service."
    echo ""
    echo "3. Restart your containers to use the new PostgreSQL database:"
    print_message $BLUE "   docker-compose up -d --force-recreate pangolin"
    echo ""
    echo "4. Verify all data has been migrated correctly by checking the Pangolin UI."
    echo ""
    print_message $RED "IMPORTANT: Backups of your original files have been created with a .backup extension."
}

# Run main function
main "$@"
