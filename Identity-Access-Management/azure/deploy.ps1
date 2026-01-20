# ===========================================
# Azure Deployment Script for Identity Access Management
# Run this script in PowerShell with Azure CLI installed
# ===========================================

param(
    [string]$ResourceGroup = "iam-resource-group",
    [string]$Location = "eastus",
    [string]$AppName = "identity-access-mgmt",
    [string]$PostgresServerName = "iam-postgres-server",
    [string]$DbName = "identity_system",
    [string]$DbUsername = "identitysystem",
    [string]$DbPassword = "ChangeThisSecurePassword123!"
)

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Azure IAM Deployment Script" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Check if Azure CLI is installed
if (!(Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "Azure CLI not found. Please install it first." -ForegroundColor Red
    Write-Host "Download from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows" -ForegroundColor Yellow
    exit 1
}

# Login check
Write-Host "`nStep 1: Checking Azure login status..." -ForegroundColor Yellow
$loginStatus = az account show 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Not logged in. Opening browser for login..." -ForegroundColor Yellow
    az login
}
Write-Host "Logged in successfully!" -ForegroundColor Green

# Create Resource Group
Write-Host "`nStep 2: Creating Resource Group..." -ForegroundColor Yellow
az group create --name $ResourceGroup --location $Location
Write-Host "Resource Group created: $ResourceGroup" -ForegroundColor Green

# Create PostgreSQL Flexible Server
Write-Host "`nStep 3: Creating Azure Database for PostgreSQL..." -ForegroundColor Yellow
Write-Host "This may take several minutes..." -ForegroundColor Gray
az postgres flexible-server create `
    --resource-group $ResourceGroup `
    --name $PostgresServerName `
    --location $Location `
    --admin-user $DbUsername `
    --admin-password $DbPassword `
    --sku-name Standard_B1ms `
    --tier Burstable `
    --storage-size 32 `
    --version 16 `
    --yes
Write-Host "PostgreSQL Server created: $PostgresServerName" -ForegroundColor Green

# Create Database
Write-Host "`nStep 4: Creating Database..." -ForegroundColor Yellow
az postgres flexible-server db create `
    --resource-group $ResourceGroup `
    --server-name $PostgresServerName `
    --database-name $DbName
Write-Host "Database created: $DbName" -ForegroundColor Green

# Configure Firewall (Allow Azure Services)
Write-Host "`nStep 5: Configuring Firewall Rules..." -ForegroundColor Yellow
az postgres flexible-server firewall-rule create `
    --resource-group $ResourceGroup `
    --name $PostgresServerName `
    --rule-name AllowAzureServices `
    --start-ip-address 0.0.0.0 `
    --end-ip-address 0.0.0.0
Write-Host "Firewall configured to allow Azure services" -ForegroundColor Green

# Create App Service Plan
Write-Host "`nStep 6: Creating App Service Plan..." -ForegroundColor Yellow
az appservice plan create `
    --name "${AppName}-plan" `
    --resource-group $ResourceGroup `
    --sku B1 `
    --is-linux
Write-Host "App Service Plan created" -ForegroundColor Green

# Create Web App
Write-Host "`nStep 7: Creating Web App..." -ForegroundColor Yellow
az webapp create `
    --resource-group $ResourceGroup `
    --plan "${AppName}-plan" `
    --name $AppName `
    --runtime "JAVA:25-java25"
Write-Host "Web App created: $AppName" -ForegroundColor Green

# Generate JWT Secret
$JwtSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 64 | ForEach-Object {[char]$_})

# Configure App Settings
Write-Host "`nStep 8: Configuring App Settings..." -ForegroundColor Yellow
$PostgresHost = "$PostgresServerName.postgres.database.azure.com"
az webapp config appsettings set `
    --resource-group $ResourceGroup `
    --name $AppName `
    --settings `
        SPRING_PROFILES_ACTIVE=prod `
        SPRING_DATASOURCE_URL="jdbc:postgresql://${PostgresHost}:5432/${DbName}?sslmode=require" `
        SPRING_DATASOURCE_USERNAME=$DbUsername `
        SPRING_DATASOURCE_PASSWORD=$DbPassword `
        JWT_SECRET_KEY=$JwtSecret `
        WEBSITES_PORT=8080
Write-Host "App settings configured" -ForegroundColor Green

# Output deployment info
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "`nYour application will be available at:" -ForegroundColor White
Write-Host "https://$AppName.azurewebsites.net" -ForegroundColor Yellow
Write-Host "`nHealth Check Endpoint:" -ForegroundColor White
Write-Host "https://$AppName.azurewebsites.net/actuator/health" -ForegroundColor Yellow
Write-Host "`nAuth Endpoints:" -ForegroundColor White
Write-Host "https://$AppName.azurewebsites.net/api/v1/auth/register" -ForegroundColor Yellow
Write-Host "https://$AppName.azurewebsites.net/api/v1/auth/login" -ForegroundColor Yellow
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "1. Build your application:" -ForegroundColor White
Write-Host "   ./mvnw clean package -DskipTests" -ForegroundColor Gray
Write-Host "`n2. Deploy your JAR file:" -ForegroundColor White
Write-Host "   az webapp deploy --resource-group $ResourceGroup --name $AppName --src-path target/Identity-Access-Management-0.0.1-SNAPSHOT.jar --type jar" -ForegroundColor Gray
Write-Host "`n3. View logs:" -ForegroundColor White
Write-Host "   az webapp log tail --resource-group $ResourceGroup --name $AppName" -ForegroundColor Gray
