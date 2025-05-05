FROM mcr.microsoft.com/dotnet/sdk:9.0-bookworm-slim AS build

RUN apt-get update
RUN apt-get install -y clang zlib1g-dev

WORKDIR /src
COPY . .
RUN dotnet publish "pam_oidc_auth.csproj" -c Release --use-current-runtime -o /app/publish