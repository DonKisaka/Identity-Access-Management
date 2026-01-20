# Azure Deployment Guide

This guide covers deploying the Identity Access Management API to Microsoft Azure using your Student subscription credits.

## Prerequisites

1. **Azure Student Account** - Sign up at [Azure for Students](https://azure.microsoft.com/en-us/free/students/)
2. **Azure CLI** - [Download](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows)
3. **Java 25** - Already configured in the project
4. **Maven** - Included via Maven Wrapper

## Quick Deployment (Automated)

### Option 1: PowerShell Script

```powershell
# Navigate to the project directory
cd Identity-Access-Management

# Run the deployment script
.\azure\deploy.ps1
```

### Option 2: Manual Step-by-Step

#### Step 1: Login to Azure

```bash
az login
```

#### Step 2: Create Resource Group

```bash
az group create --name iam-resource-group --location eastus
```

#### Step 3: Create PostgreSQL Database

```bash
az postgres flexible-server create \
  --resource-group iam-resource-group \
  --name iam-postgres-server \
  --location eastus \
  --admin-user identitysystem \
  --admin-password "YourSecurePassword123!" \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --storage-size 32 \
  --version 16
```

#### Step 4: Create the Database

```bash
az postgres flexible-server db create \
  --resource-group iam-resource-group \
  --server-name iam-postgres-server \
  --database-name identity_system
```

#### Step 5: Configure Firewall

```bash
az postgres flexible-server firewall-rule create \
  --resource-group iam-resource-group \
  --name iam-postgres-server \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

#### Step 6: Create App Service

```bash
# Create App Service Plan
az appservice plan create \
  --name iam-service-plan \
  --resource-group iam-resource-group \
  --sku B1 \
  --is-linux

# Create Web App with Java 25
az webapp create \
  --resource-group iam-resource-group \
  --plan iam-service-plan \
  --name identity-access-mgmt \
  --runtime "JAVA:25-java25"
```

#### Step 7: Configure Environment Variables

```bash
az webapp config appsettings set \
  --resource-group iam-resource-group \
  --name identity-access-mgmt \
  --settings \
    SPRING_PROFILES_ACTIVE=prod \
    SPRING_DATASOURCE_URL="jdbc:postgresql://iam-postgres-server.postgres.database.azure.com:5432/identity_system?sslmode=require" \
    SPRING_DATASOURCE_USERNAME="identitysystem" \
    SPRING_DATASOURCE_PASSWORD="YourSecurePassword123!" \
    JWT_SECRET_KEY="$(openssl rand -hex 32)" \
    WEBSITES_PORT=8080
```

#### Step 8: Build and Deploy

```bash
# Build the JAR
./mvnw clean package -DskipTests

# Deploy to Azure
az webapp deploy \
  --resource-group iam-resource-group \
  --name identity-access-mgmt \
  --src-path target/Identity-Access-Management-0.0.1-SNAPSHOT.jar \
  --type jar
```

## Post-Deployment Verification

### Check Application Status

```bash
az webapp show --resource-group iam-resource-group --name identity-access-mgmt --query "state"
```

### View Logs

```bash
az webapp log tail --resource-group iam-resource-group --name identity-access-mgmt
```

### Test Endpoints

```bash
# Health check
curl https://identity-access-mgmt.azurewebsites.net/actuator/health

# Test login endpoint
curl -X POST https://identity-access-mgmt.azurewebsites.net/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password"}'
```

## Available Endpoints

| Endpoint | Description |
|----------|-------------|
| `/actuator/health` | Health Check |
| `/api/v1/auth/register` | User Registration |
| `/api/v1/auth/login` | User Login |
| `/api/v1/auth/refresh` | Refresh Token |
| `/api/v1/auth/logout` | User Logout |
| `/api/v1/users/**` | User Management |
| `/api/v1/roles/**` | Role Management |
| `/api/v1/permissions/**` | Permission Management |

## Cost Estimation (Student Credits)

| Service | Tier | Estimated Monthly Cost |
|---------|------|----------------------|
| App Service | B1 Basic | ~$13 |
| PostgreSQL Flexible | Burstable B1ms | ~$12 |
| **Total** | | **~$25/month** |

With $100 student credits, you can run this for ~4 months.

## Cost-Saving Tips

1. **Stop when not in use**: `az webapp stop --name identity-access-mgmt --resource-group iam-resource-group`
2. **Use F1 Free tier** for development (limited features)
3. **Scale down database** when not presenting

## Cleanup (Delete All Resources)

```bash
az group delete --name iam-resource-group --yes --no-wait
```

## Troubleshooting

### Application Won't Start

1. Check logs: `az webapp log tail --name identity-access-mgmt --resource-group iam-resource-group`
2. Verify environment variables are set correctly
3. Ensure database is accessible

### Database Connection Issues

1. Verify firewall rules allow Azure services
2. Check connection string format includes `?sslmode=require`
3. Confirm username/password are correct

### Slow Startup

- First cold start can take 1-2 minutes
- Consider enabling "Always On" in App Service settings (not available in free tier)
