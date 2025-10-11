create table users (
  username text not null primary key,
  password text not null,
  is_admin boolean not null,
  public_key text not null,
  private_key text not null,
  description text not null,
  display_name text not null,
  primary_color text not null,
  tertiary_color text not null,
  secondary_color text not null,
  user_pfp_id text
);

create table chats(
  chat_id text not null primary key,
  started text not null,
  sender text not null,
  receiver text not null
);

create table messages(
  msg_id text not null primary key,
  published text not null,
  content text not null,
  sender text not null,
  receiver text not null,
  attachment text,
  chat_id text not null
);

create table user_files(
  file_id text not null primary key,
  file_path text not null,
  file_owner text not null
);

create table host_info(
  hostname text not null primary key,
  primary_color text not null,
  secondary_color text not null,
  tertiary_color text not null
);

create table invite_codes (
  code_id text not null primary key,
  invite_code text not null
);

create table user_api_tokens (
  token_id text not null primary key,
  token text not null,
  owner text not null
);
