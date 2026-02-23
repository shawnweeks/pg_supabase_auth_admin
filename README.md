### pg_supabase_auth_admin
Postgres extension to call the Supabase Auth Admin Rest API allowing you to create and administer users without using an edge function.

### Installation
1. Ensure that http and pg_tle extensions are installed in your Supabase instance.
2. Run `pg_supabase_auth_admin--0.1.0.sql` against your Supabase instance.
3. Create extension `create extension supabase_auth_admin with schema extensions;`
4. Setup service keys `select supabase_auth_admin.setup('<SUPABASE_URL>', '<SUPABASE_SERVICE_KEY>');`
5. Try it out by creating a new user `select supabase_auth_admin.create_user('dev_user_1@example.com');`

### Helpful Hints
1. The Supabase URL for local development and self hosted via docker compose will be the internal URL based on the name of the container. For example the Supabase URL if I started a local development environment in this repo would be `http://supabase_kong_pg_supabase_auth_admin:8000`.
2. For local development you can add the following to your migration to enable the required extensions `create extension http with schema extensions;` and `create extension pg_tle;`.
