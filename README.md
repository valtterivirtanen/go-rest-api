# go-rest-api

## to-do
- [x] get rid of the templates (go REST)
- [ ] refactor code to use gorilla/mux or similar routing library
- [ ] JWT authentication
  - Generate/validate token; use HMAC or private key and public key? RSA?
  - Choose claims and set them
  - Token expiration/unauthorization/renewal/etc
- [ ] remain stateless
- [ ] split the code into smaller packgages/files
- [ ] improve error handling
- [ ] add some middleware
  - authenticator
  - trimmer
  - some validation?
