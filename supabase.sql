create table if not exists public.tags (
  id text primary key check (id ~ '^[a-z0-9]{4,16}$'),
  label text not null default '',
  item text not null default '',
  spec text not null default '',
  owner_name text not null default '',
  owner_count integer not null default 0,
  theme text not null default 'basic' check (theme in ('basic', 'xmas')),
  transfer_pending boolean not null default false,
  created_at timestamptz not null default now(),
  claimed_at timestamptz
);

create table if not exists public.tag_secrets (
  tag_id text primary key references public.tags(id) on delete cascade,
  owner_hash text,
  transfer_hash text,
  transfer_expires timestamptz
);

create table if not exists public.entries (
  id uuid primary key default gen_random_uuid(),
  tag_id text not null references public.tags(id) on delete cascade,
  kind text not null,
  title text not null check (char_length(title) between 1 and 80),
  body text not null default '' check (char_length(body) <= 1000),
  happened_on text not null default '',
  created_at timestamptz not null default now()
);

alter table public.entries add column if not exists youtube text;
alter table public.entries add column if not exists media jsonb not null default '[]'::jsonb;
alter table public.entries add column if not exists owner_no integer not null default 0;

alter table public.entries drop constraint if exists entries_kind_check;
alter table public.entries add constraint entries_kind_check check (kind in ('소유', '사연', '수리', '기록', '노래'));
alter table public.entries drop constraint if exists entries_youtube_check;
alter table public.entries add constraint entries_youtube_check check (youtube is null or youtube ~ '^[A-Za-z0-9_-]{11}$');
alter table public.entries drop constraint if exists entries_media_check;
alter table public.entries add constraint entries_media_check check (jsonb_typeof(media) = 'array' and jsonb_array_length(media) <= 10);

create table if not exists public.admins (
  email text primary key
);

create table if not exists public.upload_tickets (
  path text primary key,
  tag_id text not null references public.tags(id) on delete cascade,
  kind text not null check (kind in ('image', 'video')),
  expires timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists entries_tag_idx on public.entries (tag_id, created_at);
create index if not exists upload_tickets_tag_idx on public.upload_tickets (tag_id, created_at);

alter table public.admins enable row level security;
alter table public.tags enable row level security;
alter table public.tag_secrets enable row level security;
alter table public.entries enable row level security;
alter table public.upload_tickets enable row level security;

drop policy if exists tags_read on public.tags;
drop policy if exists tags_admin_insert on public.tags;
drop policy if exists tags_admin_update on public.tags;
drop policy if exists tags_admin_delete on public.tags;
drop policy if exists entries_read on public.entries;
drop policy if exists entries_admin_delete on public.entries;

create or replace function public.memtag_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from admins where lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')))
$$;

create policy tags_read on public.tags for select using (true);
create policy tags_admin_insert on public.tags for insert to authenticated with check (memtag_is_admin() and owner_count = 0 and owner_name = '');
create policy tags_admin_update on public.tags for update to authenticated using (memtag_is_admin()) with check (memtag_is_admin());
create policy tags_admin_delete on public.tags for delete to authenticated using (memtag_is_admin());
create policy entries_read on public.entries for select using (true);
create policy entries_admin_delete on public.entries for delete to authenticated using (memtag_is_admin());

grant usage on schema public to anon, authenticated;
grant select on public.tags, public.entries to anon, authenticated;
grant insert, update, delete on public.tags to authenticated;
grant delete on public.entries to authenticated;
revoke all on public.tag_secrets from anon, authenticated;
revoke all on public.admins from anon, authenticated;
revoke all on public.upload_tickets from anon, authenticated;
revoke insert, update, delete on public.entries from anon;
revoke insert, update, delete on public.tags from anon;

create or replace function public.memtag_hash(p text)
returns text
language sql
immutable
as $$
  select encode(sha256(convert_to(coalesce(p, ''), 'UTF8')), 'hex')
$$;

create or replace function public.memtag_month()
returns text
language sql
stable
as $$
  select to_char(now() at time zone 'Asia/Seoul', 'YYYY.MM')
$$;

create or replace function public.memtag_check_owner(p_id text, p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (
    select 1 from tag_secrets
    where tag_id = p_id and owner_hash is not null and owner_hash = memtag_hash(p_token)
  ) then
    raise exception 'bad_token';
  end if;
end;
$$;

create or replace function public.memtag_ticket_ok(p_name text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from upload_tickets where path = p_name and expires > now())
$$;

create or replace function public.is_owner(p_id text, p_token text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  return exists (
    select 1 from tag_secrets
    where tag_id = p_id and owner_hash is not null and owner_hash = memtag_hash(p_token)
  );
end;
$$;

create or replace function public.claim_tag(
  p_id text, p_item text, p_spec text, p_owner text, p_since text,
  p_story text, p_theme text, p_token text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if char_length(coalesce(p_token, '')) < 16 then raise exception 'bad_token'; end if;
  if char_length(trim(coalesce(p_item, ''))) not between 1 and 60 then raise exception 'bad_item'; end if;
  if char_length(trim(coalesce(p_owner, ''))) not between 1 and 30 then raise exception 'bad_owner'; end if;
  if char_length(coalesce(p_story, '')) > 1000 then raise exception 'too_long'; end if;
  if char_length(coalesce(p_spec, '')) > 80 then raise exception 'too_long'; end if;

  update tags set
    item = trim(p_item),
    spec = trim(coalesce(p_spec, '')),
    owner_name = trim(p_owner),
    owner_count = 1,
    theme = case when p_theme = 'xmas' then 'xmas' else 'basic' end,
    claimed_at = now()
  where id = p_id and owner_count = 0;

  if not found then
    if exists (select 1 from tags where id = p_id) then
      raise exception 'already_claimed';
    end if;
    raise exception 'no_tag';
  end if;

  insert into tag_secrets (tag_id, owner_hash)
  values (p_id, memtag_hash(p_token))
  on conflict (tag_id) do update set owner_hash = excluded.owner_hash, transfer_hash = null, transfer_expires = null;

  insert into entries (tag_id, kind, title, body, happened_on, owner_no)
  values (p_id, '소유', '초대 주인이 이야기를 시작했어요', coalesce(p_story, ''),
          coalesce(nullif(trim(p_since), ''), memtag_month()), 1);
end;
$$;

create or replace function public.request_upload(p_id text, p_token text, p_type text, p_ext text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_ext text := lower(coalesce(p_ext, ''));
  v_path text;
begin
  perform memtag_check_owner(p_id, p_token);
  if p_type = 'image' and v_ext not in ('jpg', 'jpeg', 'png', 'webp', 'gif') then raise exception 'bad_media'; end if;
  if p_type = 'video' and v_ext not in ('mp4', 'webm', 'mov') then raise exception 'bad_media'; end if;
  if p_type not in ('image', 'video') then raise exception 'bad_media'; end if;
  if (select count(*) from upload_tickets where tag_id = p_id and created_at > now() - interval '1 hour') >= 40 then
    raise exception 'too_many';
  end if;
  v_path := p_id || '/' || to_char(now() at time zone 'Asia/Seoul', 'YYYYMMDD') || '-'
            || substr(md5(random()::text || clock_timestamp()::text || p_id), 1, 16) || '.' || v_ext;
  insert into upload_tickets (path, tag_id, kind, expires) values (v_path, p_id, p_type, now() + interval '30 minutes');
  return v_path;
end;
$$;

drop function if exists public.add_entry(text, text, text, text, text, text);

create or replace function public.add_entry(
  p_id text, p_token text, p_kind text, p_title text, p_body text, p_date text,
  p_media jsonb default '[]'::jsonb, p_youtube text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_media jsonb := '[]'::jsonb;
  v_item jsonb;
  v_owner integer;
  v_new uuid;
begin
  perform memtag_check_owner(p_id, p_token);
  if p_kind not in ('사연', '수리', '기록', '노래') then raise exception 'bad_kind'; end if;
  if char_length(trim(coalesce(p_title, ''))) not between 1 and 80 then raise exception 'bad_title'; end if;
  if char_length(coalesce(p_body, '')) > 1000 then raise exception 'too_long'; end if;
  if p_youtube is not null and p_youtube !~ '^[A-Za-z0-9_-]{11}$' then raise exception 'bad_youtube'; end if;
  if p_kind = '노래' and p_youtube is null then raise exception 'bad_youtube'; end if;
  if p_media is null then p_media := '[]'::jsonb; end if;
  if jsonb_typeof(p_media) <> 'array' or jsonb_array_length(p_media) > 10 then raise exception 'bad_media'; end if;

  for v_item in select * from jsonb_array_elements(p_media) loop
    if not exists (
      select 1 from upload_tickets t
      where t.path = v_item ->> 'path' and t.tag_id = p_id and t.kind = v_item ->> 'type'
    ) then
      raise exception 'bad_media';
    end if;
    if not exists (
      select 1 from storage.objects o where o.bucket_id = 'memtag-media' and o.name = v_item ->> 'path'
    ) then
      raise exception 'bad_media';
    end if;
    v_media := v_media || jsonb_build_array(jsonb_build_object('path', v_item ->> 'path', 'type', v_item ->> 'type'));
  end loop;

  select owner_count into v_owner from tags where id = p_id;

  insert into entries (tag_id, kind, title, body, happened_on, youtube, media, owner_no)
  values (p_id, p_kind, trim(p_title), coalesce(p_body, ''),
          coalesce(nullif(trim(p_date), ''), memtag_month()), p_youtube, v_media, v_owner)
  returning id into v_new;
  return v_new;
end;
$$;

create or replace function public.delete_entry(p_id text, p_token text, p_entry uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform memtag_check_owner(p_id, p_token);
  delete from entries e
  using tags t
  where e.id = p_entry and e.tag_id = p_id and t.id = p_id
    and e.owner_no = t.owner_count and e.kind <> '소유';
  if not found then raise exception 'cannot_delete'; end if;
end;
$$;

create or replace function public.update_tag(
  p_id text, p_token text, p_item text, p_spec text, p_theme text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform memtag_check_owner(p_id, p_token);
  if char_length(trim(coalesce(p_item, ''))) not between 1 and 60 then raise exception 'bad_item'; end if;
  if char_length(coalesce(p_spec, '')) > 80 then raise exception 'too_long'; end if;
  update tags set
    item = trim(p_item),
    spec = trim(coalesce(p_spec, '')),
    theme = case when p_theme = 'xmas' then 'xmas' else 'basic' end
  where id = p_id;
end;
$$;

create or replace function public.start_transfer(p_id text, p_token text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_code text;
begin
  perform memtag_check_owner(p_id, p_token);
  v_code := upper(substr(md5(random()::text || clock_timestamp()::text || p_id), 1, 8));
  update tag_secrets set transfer_hash = memtag_hash(v_code), transfer_expires = now() + interval '7 days'
  where tag_id = p_id;
  update tags set transfer_pending = true where id = p_id;
  return v_code;
end;
$$;

create or replace function public.cancel_transfer(p_id text, p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform memtag_check_owner(p_id, p_token);
  update tag_secrets set transfer_hash = null, transfer_expires = null where tag_id = p_id;
  update tags set transfer_pending = false where id = p_id;
end;
$$;

create or replace function public.accept_transfer(
  p_id text, p_code text, p_owner text, p_story text, p_token text
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if char_length(coalesce(p_token, '')) < 16 then raise exception 'bad_token'; end if;
  if char_length(trim(coalesce(p_owner, ''))) not between 1 and 30 then raise exception 'bad_owner'; end if;
  if char_length(coalesce(p_story, '')) > 1000 then raise exception 'too_long'; end if;

  if not exists (
    select 1 from tag_secrets
    where tag_id = p_id
      and transfer_hash is not null
      and transfer_hash = memtag_hash(upper(trim(p_code)))
      and transfer_expires > now()
  ) then
    raise exception 'bad_code';
  end if;

  update tags set
    owner_name = trim(p_owner),
    owner_count = owner_count + 1,
    transfer_pending = false
  where id = p_id
  returning owner_count into v_count;

  update tag_secrets set
    owner_hash = memtag_hash(p_token),
    transfer_hash = null,
    transfer_expires = null
  where tag_id = p_id;

  insert into entries (tag_id, kind, title, body, happened_on, owner_no)
  values (p_id, '소유', v_count || '번째 주인에게 양도되었어요', coalesce(p_story, ''), memtag_month(), v_count);

  return v_count;
end;
$$;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('memtag-media', 'memtag-media', true, 52428800,
        array['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm', 'video/quicktime'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists memtag_media_insert on storage.objects;
drop policy if exists memtag_media_select on storage.objects;
create policy memtag_media_insert on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'memtag-media' and public.memtag_ticket_ok(name));
create policy memtag_media_select on storage.objects for select to anon, authenticated
  using (bucket_id = 'memtag-media');

revoke all on function public.memtag_check_owner(text, text) from public, anon, authenticated;
grant execute on function public.memtag_ticket_ok(text) to anon, authenticated;
grant execute on function public.memtag_is_admin() to anon, authenticated;
grant execute on function public.is_owner(text, text) to anon, authenticated;
grant execute on function public.claim_tag(text, text, text, text, text, text, text, text) to anon, authenticated;
grant execute on function public.request_upload(text, text, text, text) to anon, authenticated;
grant execute on function public.add_entry(text, text, text, text, text, text, jsonb, text) to anon, authenticated;
grant execute on function public.delete_entry(text, text, uuid) to anon, authenticated;
grant execute on function public.update_tag(text, text, text, text, text) to anon, authenticated;
grant execute on function public.start_transfer(text, text) to anon, authenticated;
grant execute on function public.cancel_transfer(text, text) to anon, authenticated;
grant execute on function public.accept_transfer(text, text, text, text, text) to anon, authenticated;
