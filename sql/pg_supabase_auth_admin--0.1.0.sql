SELECT pgtle.install_extension(
  -- Extension name
  'supabase_auth_admin',

  -- Version
  '0.0.1',

  -- Description
  'Supabase Auth Admin REST API wrapper using pg_vault and the http extension',

  -- Extension body SQL (everything that runs at CREATE EXTENSION time)
  $ext$

-- ============================================================
-- SETUP SCHEMA
-- ============================================================

create schema if not exists supabase_auth_admin;

-- Prevent unprivileged access from public.
alter default privileges in schema supabase_auth_admin revoke all on functions from public;

-- TODO - Set RLS on Supabase Vault

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
    http_header('Authorization', format('Bearer %s', v_api_key)),
    http_header('apikey', v_api_key)
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
set search_path = supabase_auth_admin, extensions
as $$
declare
  v_url text;
  v_response http_response;
  v_status int;
  v_content text;
begin
  v_url := format('%s/auth/v1/%s', _get_supabase_url(), p_path);

  v_response := http((
      p_method,
      v_url,
      _build_headers(),
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

-- List users with pagination.
-- SELECT supabase_auth_admin.list_users();
-- SELECT supabase_auth_admin.list_users(p_page => 2, p_per_page => 100);
create or replace function supabase_auth_admin.list_users(
  p_page int default 1,
  p_per_page int default 50
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
begin
  return _request(
    'get',
    format('admin/users?page=%s&per_page=%s', p_page, p_per_page)
  );
end;
$$;

-- Get a single user by UUID.
-- SELECT supabase_auth_admin.get_user('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
create or replace function supabase_auth_admin.get_user(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
declare
  v_body jsonb;
begin
  return _request(
    'get', 
    format('admin/users/%s', p_user_id::text)
    );
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
  p_phone_confirm boolean default false,
  p_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
declare
  v_body jsonb;
begin
  v_body := jsonb_build_object(
    'id', p_id,
    'email', p_email,
    'email_confirm', p_email_confirm,
    'password', p_password,
    'phone', p_phone,
    'user_metadata', p_user_metadata,
    'app_metadata',  p_app_metadata,
    'phone_confirm', p_phone_confirm
    );

  return _request('POST', 'admin/users', v_body);
end;
$$;

-- Update an existing user.
-- SELECT supabase_auth_admin.update_user('uuid', p_email => 'new@example.com');
-- SELECT supabase_auth_admin.update_user('uuid', p_ban_duration => '24h');   -- temp ban
-- SELECT supabase_auth_admin.update_user('uuid', p_ban_duration => 'none');  -- unban
create or replace function supabase_auth_admin.update_user(
  p_user_id uuid,
  p_email text default null,
  p_password text default null,
  p_phone text default null,
  p_user_metadata jsonb default null,
  p_app_metadata jsonb default null,
  p_email_confirm boolean default null,
  p_phone_confirm boolean default null,
  p_ban_duration text default null  -- '24h' | '876000h' (permanent) | 'none'
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
declare
  v_body jsonb;
begin
  v_body := jsonb_build_object(
    'email', p_email,
    'password', p_password,
    'phone', p_phone,
    'user_metadata', p_user_metadata,
    'app_metadata',  p_app_metadata,
    'email_confirm', p_email_confirm,
    'phone_confirm', p_phone_confirm,
    'ban_duration',  p_ban_duration
    );

  return _request(
    'put',
    format('admin/users/%s', p_user_id::text),
    v_body
    );
end;
$$;

-- Delete a user (hard delete by default).
-- SELECT supabase_auth_admin.delete_user('uuid');
-- SELECT supabase_auth_admin.delete_user('uuid', p_should_soft_delete => true);
create or replace function supabase_auth_admin.delete_user(
  p_user_id uuid,
  p_should_soft_delete boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
declare
  v_body jsonb;
begin
  v_body := jsonb_build_object(
    'should_soft_delete', p_should_soft_delete
    );
  return _request(
    'delete',
    format('admin/users/%s', p_user_id::text),
    v_body
    );
end;
$$;

-- ============================================================
-- INVITATIONS
-- ============================================================

-- Invite a user by email.
-- SELECT supabase_auth_admin.invite_user_by_email('newuser@example.com');
-- SELECT supabase_auth_admin.invite_user_by_email('newuser@example.com', '{"team":42}', 'https://app.com/welcome');
create or replace function supabase_auth_admin.invite_user_by_email(
  p_email text,
  p_data jsonb default null,
  p_redirect_to text default null
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
declare
  v_body jsonb;
begin
  v_body := jsonb_build_object(
    'email', p_email,
    'data', p_data,
    'redirect_to', p_redirect_to
    );

  return _request('post', 'invite', v_body);
end;
$$;

-- ============================================================
-- MAGIC LINKS & OTP
-- ============================================================

-- Generate an action link for a user.
-- Link types: signup | magiclink | recovery | email_change_new | email_change_current
--
-- SELECT supabase_auth_admin.generate_link('magiclink', 'user@example.com');
-- SELECT supabase_auth_admin.generate_link('recovery', 'user@example.com');
-- SELECT supabase_auth_admin.generate_link('signup', 'new@example.com', p_password => 'secret');
create or replace function supabase_auth_admin.generate_link(
  p_type text,
  p_email text,
  p_password text default null,
  p_new_email text default null,
  p_data jsonb default null,
  p_redirect_to text default null
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
declare
  v_body jsonb;
begin
  v_body := jsonb_build_object(
    'type', p_type,
    'email', p_email,
    'password', p_password,
    'new_email', p_new_email,
    'data', p_data,
    'redirect_to', p_redirect_to
    );

  return _request('post', 'admin/generate_link', v_body);
end;
$$;

-- ============================================================
-- MFA FACTORS
-- ============================================================

-- List all enrolled MFA factors for a user.
-- SELECT supabase_auth_admin.list_factors('uuid');
create or replace function supabase_auth_admin.list_factors(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
begin
  return _request(
    'get',
    format('admin/users/%s/factors', p_user_id::text)
    );
end;
$$;

-- Delete a specific MFA factor.
-- SELECT supabase_auth_admin.delete_factor('user-uuid', 'factor-uuid');
create or replace function supabase_auth_admin.delete_factor(
  p_user_id uuid,
  p_factor_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = supabase_auth_admin
as $$
begin
  return _request(
    'delete',
    format('admin/users/%s/factors/%s', p_user_id::text, p_factor_id::text)
    );
end;
$$;

  $ext$,
  '{supabase_vault, http}'
  );