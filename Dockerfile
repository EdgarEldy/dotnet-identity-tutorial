FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/DotnetIdentityTutorial/DotnetIdentityTutorial.csproj src/DotnetIdentityTutorial/
RUN dotnet restore src/DotnetIdentityTutorial/DotnetIdentityTutorial.csproj

COPY src/DotnetIdentityTutorial/ src/DotnetIdentityTutorial/
RUN dotnet publish src/DotnetIdentityTutorial/DotnetIdentityTutorial.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

COPY --from=build /app ./

ENTRYPOINT ["dotnet", "DotnetIdentityTutorial.dll"]
