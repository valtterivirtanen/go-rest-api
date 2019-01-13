# go-rest-api

## to-do
- [x] get rid of the templates (go REST)
- [x] refactor code to use gorilla/mux or similar routing library
- JWT authentication
  - [x] Generate/validate token; use HMAC or private key and public key? RSA?
  - [x] Choose claims and set them
  - [x] Token expiration
  - [ ] Token renewal
  - [ ] nbf / notbeforetime claim set and verified
- [ ] remain stateless
- [ ] split the code into smaller packgages/files
- [ ] improve error handling
- add some middleware
  - [x] authenticator
  - [ ] trimmer
  - [ ] some validation?
- [ ] create helper function for JSON responses
- [ ] create helper function for http error responses
- [ ] create helper function for database calls
- [ ] improve API security https://github.com/shieldfy/API-Security-Checklist
- [ ] log everything and manage logs
- [ ] (unit)tests for everything
- [ ] one (more) checklist to look at https://www.kennethlange.com/rest-api-checklist/
- [ ] cache db queries
- [ ] concurrent calls? go-routines
- [ ] add roles/permissions to users
- [ ] API documentation
- [ ] HTTP ETags
- [ ] Ability to cancel requests using context package
- [ ] Throttle to limit request frequency (429 "Too Many Requests")
- [ ] Ability to respond in xml-format also, if requested so



## db structure @ the moment

TABLE **users**:

| Column | Type | Nullable |
| --- |:---:|---:|
| id | SERIAL | NOT NULL|
| username | VARCHAR | NOT NULL |
| email | VARCHAR | |
| password | VARCHAR | NOT NULL |

