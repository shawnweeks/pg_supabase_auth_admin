-- \echo Use "CREATE EXTENSION pg_supabase_auth_admin" to load this file. \quit

-- ============================================================
-- SETUP SCHEMA
-- ============================================================

create schema if not exists supabase_auth_admin;

-- ============================================================
-- INTERNAL HELPERS
-- Private functions are revoked from PUBLIC at the bottom.
-- ============================================================

-- Fetch the service_role key from Vault.
create or replace function supabase_auth_admin._get_service_role_key()
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_api_key text;
begin
  select decrypted_secret into v_api_key
    from vault.decrypted_secrets
    where name = 'supabase_service_role_key';

  if not found
  then
    raise exception
      'supabase_service_role_key not found in vault. '
      'run: select supabase_auth_admin.setup(''https://xxxx.supabase.co'', ''<service_role_key>'');';
  end if;

  return v_api_key;
end;
$$;

-- Fetch the Supabase project URL from Vault.
create or replace function supabase_auth_admin._get_supabase_url()
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_url text;
begin
  select decrypted_secret into v_url
    from vault.decrypted_secrets
    where name = 'supabase_url';

  if v_url is null then
    raise exception
      'supabase_url not found in vault. '
      'run: select supabase_auth_admin.setup(''https://xxxx.supabase.co'', ''<service_role_key>'');';
  end if;

  return v_url;
end;
$$;

-- Build the standard HTTP headers for every Auth Admin request.
create or replace function supabase_auth_admin._build_headers()
returns http_header[]
language plpgsql
security definer
set search_path = extensions
as $$
declare
  v_api_key text;
begin
  v_api_key := supabase_auth_admin._get_service_role_key();
  return array[
    http_header('Authorization', 'Bearer ' || v_api_key),
    http_header('apikey', v_api_key),
    http_header('Content-Type',  'application/json')
  ];
end;
$$;

-- Core dispatcher: build the full URL, fire the HTTP call, raise on non-2xx.
create or replace function supabase_auth_admin._request(
  p_method text,
  p_path text,
  p_body jsonb default null
)
returns jsonb
language plpgsql
security definer
set search_path = extensions
as $$
declare
  v_url text;
  v_response http_response;
  v_status int;
  v_content text;
begin
  v_url := supabase_auth_admin._get_supabase_url() || '/auth/v1/admin' || p_path;
  
  v_response := http((
      p_method,
      v_url,
      supabase_auth_admin._build_headers(),
      'application/json',
      case when p_body is not null then p_body::text else null end
    )::http_request);

  v_status := v_response.status;
  v_content := v_response.content;

  if v_status < 200 or v_status >= 300 then
    raise exception 'auth admin api error % on % %: %', v_status, p_method, p_path, v_content;
  end if;

  if v_content is null or v_content = '' then
    return '{}'::jsonb;
  end if;

  return v_content::jsonb;
end;
$$;

revoke all on function supabase_auth_admin._get_service_role_key() from public;
revoke all on function supabase_auth_admin._get_supabase_url() from public;
revoke all on function supabase_auth_admin._build_headers() from public;
revoke all on function supabase_auth_admin._request(text, text, jsonb) from public;

-- ============================================================
-- SETUP HELPER
-- ============================================================

-- Add or update credentials in the Supabase Vault
-- SELECT supabase_auth_admin.setup('https://abcdefgh.supabase.co', 'eyJhbGci...');
create or replace function supabase_auth_admin.setup(
  p_supabase_url text,
  p_service_role_key text
)
returns text
language plpgsql
set search_path = ''
as $$
declare
  v_url_id uuid;
  v_api_key_id uuid;
begin
  select id into v_url_id
    from vault.decrypted_secrets
    where name = 'supabase_url';

  if not found
    then perform vault.create_secret(rtrim(trim(p_supabase_url), '/'), 'supabase_url');
    else perform vault.update_secret(v_url_id,rtrim(trim(p_supabase_url), '/'));
  end if;

  select id into v_api_key_id
    from vault.decrypted_secrets
    where name = 'supabase_service_role_key';

  if not found
    then perform vault.create_secret(trim(p_service_role_key), 'supabase_service_role_key');
    else perform vault.update_secret(v_api_key_id, trim(p_service_role_key));
  end if;

  return 'supabase_auth_admin: credentials stored in vault successfully.';
end;
$$;

-- ============================================================
-- USER MANAGEMENT
-- ============================================================

-- Get a single user by UUID.
-- SELECT supabase_auth_admin.get_user('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
create or replace function supabase_auth_admin.get_user(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_body jsonb;
begin
  return supabase_auth_admin._request('GET', '/users/' || p_user_id::text);
end;
$$;

-- Create a new user.
-- select supabase_auth_admin.create_user(p_email => 'alice@example.com', p_email_confirm => true);
create or replace function supabase_auth_admin.create_user(
  p_email text default null,
  p_password text default null,
  p_phone text default null,
  p_user_metadata jsonb default null,
  p_app_metadata jsonb default null,
  p_email_confirm boolean default false,
  p_phone_confirm boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_body jsonb := '{}'::jsonb;
begin
  v_body := jsonb_build_object(
    'email', p_email,
    'email_confirm', p_email_confirm,
    'password', p_password,
    'phone', p_phone,
    'user_metadata', p_user_metadata,
    'app_metadata',  p_app_metadata,
    'phone_confirm', p_phone_confirm
    );

  return supabase_auth_admin._request('POST', '/users', v_body);
end;
$$;