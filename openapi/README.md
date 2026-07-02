# Phoenix Security API — OpenAPI Spec

`phoenix-security-api-v1.27.yaml` is an OpenAPI 3.0.3 description of the Phoenix Security Enterprise API v1.27 (48 documented endpoints, including alias and name-selector variants). Human-readable docs live in [`../docs/API_REFERENCE.md`](../docs/API_REFERENCE.md).

## View in Swagger UI

From the repository root:

```bash
docker run -p 8080:8080 \
  -e SWAGGER_JSON=/spec/phoenix-security-api-v1.27.yaml \
  -v $(pwd)/openapi:/spec \
  swaggerapi/swagger-ui
```

Then open http://localhost:8080.

## Import into Postman / Insomnia

- **Postman**: File > Import > select `phoenix-security-api-v1.27.yaml` (imported as a collection; pick your server from the collection variables).
- **Insomnia**: Application menu > Import > From File > select the YAML.

After importing, set Basic auth (Client ID/Secret) on `GET /v1/auth/access_token`, then use the returned token as the Bearer token for everything else.

## Generate API clients

With [openapi-generator](https://openapi-generator.tech):

```bash
openapi-generator-cli generate \
  -i openapi/phoenix-security-api-v1.27.yaml \
  -g python \
  -o clients/python
```

Swap `-g python` for `typescript-fetch`, `go`, `java`, etc. as needed.

## Notes

- Global security is `bearerAuth`; only the token endpoint uses `basicAuth`.
- Servers include prod, demo, PoC, and a templated dedicated-enterprise URL (`https://api.{tenant}.securityphoenix.cloud`).
- Endpoints that identify entities by name (selector variants) are modeled as separate paths without the ID segment (e.g. `PUT /v1/applications/tags`).
