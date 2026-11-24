create table if not exists public.hm_couples (
  code text primary key check (code ~ '^[a-z0-9]{4,16}$'),
  item text not null default '',
  met date,
  created_by text check (created_by in ('pink', 'blue')),
  diary_at timestamptz,
  pink_hash text,
  blue_hash text,
  created_at timestamptz not null default now()
);

create table if not exists public.hm_entries (
  id uuid primary key default gen_random_uuid(),
  code text not null references public.hm_couples(code) on delete cascade,
  seat text not null check (seat in ('pink', 'blue')),
  title text not null check (char_length(title) between 1 and 30),
  body text not null default '' check (char_length(body) <= 300),
  stamp text not null check (stamp in ('smile', 'flutter', 'kiss', 'laugh', 'sulk', 'moved', 'miss', 'cheer', 'd100', 'd200', 'y1', 'y2')),
  day date not null,
  created_at timestamptz not null default now()
);

create table if not exists public.hm_replies (
  entry_id uuid primary key references public.hm_entries(id) on delete cascade,
  code text not null references public.hm_couples(code) on delete cascade,
  seat text not null check (seat in ('pink', 'blue')),
  stamp text not null check (stamp in ('smile', 'flutter', 'kiss', 'laugh', 'sulk', 'moved', 'miss', 'cheer', 'd100', 'd200', 'y1', 'y2')),
  body text not null default '' check (char_length(body) <= 40),
  created_at timestamptz not null default now()
);

create index if not exists hm_entries_code_idx on public.hm_entries (code, created_at desc);
create index if not exists hm_replies_code_idx on public.hm_replies (code);

alter table public.hm_couples enable row level security;
alter table public.hm_entries enable row level security;
alter table public.hm_replies enable row level security;

revoke all on public.hm_couples from anon, authenticated;
revoke all on public.hm_entries from anon, authenticated;
revoke all on public.hm_replies from anon, authenticated;

create or replace function public.hm_hash(p text)
returns text
language sql
immutable
as $$
  select encode(sha256(convert_to(coalesce(p, ''), 'UTF8')), 'hex')
$$;

create or replace function public.hm_today()
returns date
language sql
stable
as $$
  select (now() at time zone 'Asia/Seoul')::date
$$;

create or replace function public.hm_ms(t timestamptz)
returns bigint
language sql
immutable
as $$
  select (extract(epoch from t) * 1000)::bigint
$$;

create or replace function public.hm_seat_of(p_code text, p_token text)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select case
    when char_length(coalesce(p_token, '')) < 16 then null
    when c.pink_hash = hm_hash(p_token) then 'pink'
    when c.blue_hash = hm_hash(p_token) then 'blue'
  end
  from hm_couples c where c.code = p_code
$$;

create or replace function public.hm_state(p_code text, p_token text)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  c hm_couples;
begin
  if coalesce(p_code, '') !~ '^[a-z0-9]{4,16}$' then raise exception 'bad_code'; end if;
  select * into c from hm_couples where code = p_code;
  if not found then
    return jsonb_build_object('exists', false, 'pink', false, 'blue', false, 'me', null, 'diary', null, 'entries', '[]'::jsonb);
  end if;
  return jsonb_build_object(
    'exists', true,
    'pink', c.pink_hash is not null,
    'blue', c.blue_hash is not null,
    'me', hm_seat_of(p_code, p_token),
    'diary', case when c.diary_at is null then null else jsonb_build_object(
      'item', c.item, 'met', to_char(c.met, 'YYYY-MM-DD'), 'by', c.created_by, 'created', hm_ms(c.diary_at)) end,
    'entries', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', e.id, 'by', e.seat, 'title', e.title, 'body', e.body, 'stamp', e.stamp,
        'date', to_char(e.day, 'YYYY-MM-DD'), 't', hm_ms(e.created_at),
        'reply', case when r.entry_id is null then null else jsonb_build_object(
          'by', r.seat, 'stamp', r.stamp, 'text', r.body, 't', hm_ms(r.created_at)) end
      ) order by e.created_at desc)
      from (select * from hm_entries where code = p_code order by created_at desc limit 500) e
      left join hm_replies r on r.entry_id = e.id
    ), '[]'::jsonb)
  );
end;
$$;

create or replace function public.hm_claim(p_code text, p_seat text, p_token text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_have text;
begin
  if coalesce(p_code, '') !~ '^[a-z0-9]{4,16}$' then raise exception 'bad_code'; end if;
  if p_seat not in ('pink', 'blue') then raise exception 'bad_seat'; end if;
  if char_length(coalesce(p_token, '')) < 16 then raise exception 'bad_token'; end if;

  insert into hm_couples (code) values (p_code) on conflict (code) do nothing;

  v_have := hm_seat_of(p_code, p_token);
  if v_have is not null then return v_have; end if;

  if p_seat = 'pink' then
    update hm_couples set pink_hash = hm_hash(p_token) where code = p_code and pink_hash is null;
  else
    update hm_couples set blue_hash = hm_hash(p_token) where code = p_code and blue_hash is null;
  end if;
  if not found then raise exception 'seat_taken'; end if;
  return p_seat;
end;
$$;

create or replace function public.hm_release(p_code text, p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_seat text := hm_seat_of(p_code, p_token);
begin
  if v_seat is null then raise exception 'not_seated'; end if;
  if v_seat = 'pink' then
    update hm_couples set pink_hash = null where code = p_code;
  else
    update hm_couples set blue_hash = null where code = p_code;
  end if;
end;
$$;

create or replace function public.hm_create(p_code text, p_token text, p_item text, p_met text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_seat text := hm_seat_of(p_code, p_token);
  v_met date;
begin
  if v_seat is null then raise exception 'not_seated'; end if;
  if char_length(trim(coalesce(p_item, ''))) not between 1 and 24 then raise exception 'bad_item'; end if;
  if coalesce(p_met, '') !~ '^\d{4}-\d{2}-\d{2}$' then raise exception 'bad_date'; end if;
  v_met := p_met::date;
  if v_met > hm_today() or v_met < date '1970-01-01' then raise exception 'bad_date'; end if;

  update hm_couples set item = trim(p_item), met = v_met, created_by = v_seat, diary_at = now()
  where code = p_code and diary_at is null;
  if not found then raise exception 'diary_exists'; end if;
end;
$$;

create or replace function public.hm_add_entry(p_code text, p_token text, p_title text, p_body text, p_stamp text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_seat text := hm_seat_of(p_code, p_token);
  v_id uuid;
begin
  if v_seat is null then raise exception 'not_seated'; end if;
  if not exists (select 1 from hm_couples where code = p_code and diary_at is not null) then raise exception 'no_diary'; end if;
  if char_length(trim(coalesce(p_title, ''))) not between 1 and 30 then raise exception 'bad_title'; end if;
  if char_length(coalesce(p_body, '')) > 300 then raise exception 'too_long'; end if;
  if (select count(*) from hm_entries where code = p_code and created_at > now() - interval '1 hour') >= 60 then
    raise exception 'too_many';
  end if;

  insert into hm_entries (code, seat, title, body, stamp, day)
  values (p_code, v_seat, trim(p_title), coalesce(p_body, ''), p_stamp, hm_today())
  returning id into v_id;
  return v_id;
end;
$$;

create or replace function public.hm_add_reply(p_code text, p_token text, p_entry uuid, p_body text, p_stamp text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_seat text := hm_seat_of(p_code, p_token);
begin
  if v_seat is null then raise exception 'not_seated'; end if;
  if char_length(coalesce(p_body, '')) > 40 then raise exception 'too_long'; end if;
  if not exists (select 1 from hm_entries where id = p_entry and code = p_code and seat <> v_seat) then
    raise exception 'cannot_reply';
  end if;

  insert into hm_replies (entry_id, code, seat, stamp, body)
  values (p_entry, p_code, v_seat, p_stamp, trim(coalesce(p_body, '')))
  on conflict (entry_id) do nothing;
  if not found then raise exception 'already_replied'; end if;
end;
$$;

revoke all on function public.hm_seat_of(text, text) from public, anon, authenticated;
grant execute on function public.hm_state(text, text) to anon, authenticated;
grant execute on function public.hm_claim(text, text, text) to anon, authenticated;
grant execute on function public.hm_release(text, text) to anon, authenticated;
grant execute on function public.hm_create(text, text, text, text) to anon, authenticated;
grant execute on function public.hm_add_entry(text, text, text, text, text) to anon, authenticated;
grant execute on function public.hm_add_reply(text, text, uuid, text, text) to anon, authenticated;
