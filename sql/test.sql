\pset pager off

create extension supabase_auth_admin with schema extensions;
select supabase_auth_admin.setup('http://supabase_kong_pg_supabase_auth_admin:8000', 'sb_secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz');
select supabase_auth_admin.create_user(p_id => '11111111-1111-1111-1111-111111111111', p_email => 'dev_user_1@example.com');

select supabase_auth_admin.list_users();
select supabase_auth_admin.get_user('11111111-1111-1111-1111-111111111111');
select supabase_auth_admin.update_user('11111111-1111-1111-1111-111111111111', p_email => 'dev_user_2@example.com');
select supabase_auth_admin.update_user('11111111-1111-1111-1111-111111111111', p_ban_duration => '24h'); -- temp ban
select supabase_auth_admin.update_user('11111111-1111-1111-1111-111111111111', p_ban_duration => 'none'); -- unban

select supabase_auth_admin.invite_user_by_email('dev_user_2@example.com');
select supabase_auth_admin.invite_user_by_email('dev_user_3@example.com', '{"team":42}', 'https://app.example.com/welcome');

select supabase_auth_admin.generate_link('magiclink', 'dev_user_4@example.com');
select supabase_auth_admin.generate_link('recovery', 'dev_user_2@example.com');
select supabase_auth_admin.generate_link('signup', 'dev_user_6@example.com', p_password => 'secret');

select supabase_auth_admin.list_factors('11111111-1111-1111-1111-111111111111');

-- Don't have a way to setup MFA automatically but I have to assume it will work.
-- select supabase_auth_admin.delete_factor('user-uuid', 'factor-uuid');

select supabase_auth_admin.delete_user('11111111-1111-1111-1111-111111111111', p_should_soft_delete => true);
select supabase_auth_admin.delete_user('11111111-1111-1111-1111-111111111111');
