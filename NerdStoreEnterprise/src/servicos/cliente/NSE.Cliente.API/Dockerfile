FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["src/servicos/cliente/NSE.Cliente.API/NSE.Cliente.API.csproj", "NSE.Cliente.API/"]
RUN dotnet restore "src/servicos/cliente/NSE.Cliente.API/NSE.Cliente.API.csproj"
COPY . .
WORKDIR "/src/NSE.Cliente.API"
RUN dotnet build "NSE.Cliente.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NSE.Cliente.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NSE.Cliente.API.dll"]
