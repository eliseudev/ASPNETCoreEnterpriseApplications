FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["src/servicos/pedido/NSE.Pedido.API/NSE.Pedido.API.csproj", "NSE.Pedido.API/"]
RUN dotnet restore "src/servicos/pedido/NSE.Pedido.API/NSE.Pedido.API.csproj"
COPY . .
WORKDIR "/src/NSE.Pedido.API"
RUN dotnet build "NSE.Pedido.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NSE.Pedido.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NSE.Pedido.API.dll"]
