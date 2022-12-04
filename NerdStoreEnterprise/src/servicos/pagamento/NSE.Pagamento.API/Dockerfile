FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["src/servicos/pagamento/NSE.Pagamento.API/NSE.Pagamento.API.csproj", "NSE.Pagamento.API/"]
RUN dotnet restore "src/servicos/pagamento/NSE.Pagamento.API/NSE.Pagamento.API.csproj"
COPY . .
WORKDIR "/src/NSE.Pagamento.API"
RUN dotnet build "NSE.Pagamento.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NSE.Pagamento.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NSE.Pagamento.API.dll"]
