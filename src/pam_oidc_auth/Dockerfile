FROM mcr.microsoft.com/dotnet/sdk:10.0-preview-aot AS build

WORKDIR /src
COPY . .
RUN dotnet publish "pam_oidc_auth.csproj" -c Release --use-current-runtime -o /app/publish
RUN ls /app/publish