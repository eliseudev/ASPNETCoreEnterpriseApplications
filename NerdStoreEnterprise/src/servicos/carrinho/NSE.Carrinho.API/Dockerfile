FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["src/servicos/carrinho/NSE.Carrinho.API/NSE.Carrinho.API.csproj", "NSE.Carrinho.API/"]
RUN dotnet restore "src/servicos/carrinho/NSE.Carrinho.API/NSE.Carrinho.API.csproj"
COPY . .
WORKDIR "/src/NSE.Carrinho.API"
RUN dotnet build "NSE.Carrinho.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NSE.Carrinho.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NSE.Carrinho.API.dll"]
