FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["src/servicos/catalogo/NSE.Calalogo.API/NSE.Calalogo.API.csproj", "NSE.Calalogo.API/"]
RUN dotnet restore "src/servicos/catalogo/NSE.Calalogo.API/NSE.Calalogo.API.csproj"
COPY . .
WORKDIR "/src/NSE.Calalogo.API"
RUN dotnet build "NSE.Calalogo.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NSE.Calalogo.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NSE.Calalogo.API.dll"]
