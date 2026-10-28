FROM mcr.microsoft.com/dotnet/aspnet:9.0.21-noble-chiseled@sha256:9a7a9cf1bfd0ad64df17fd156345e3a36df1be26d92c8230bfc212f6627a6b41
WORKDIR /app
COPY --chown=app:app publish/ ./
USER app
ENV ASPNETCORE_HTTP_PORTS=8080
ENV Data__Path=/app/data
EXPOSE 8080
ENTRYPOINT ["dotnet", "AgentHarness.InternalApi.dll"]
