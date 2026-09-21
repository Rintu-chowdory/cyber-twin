
CREATE TABLE customers (
  id serial PRIMARY KEY, name text, email text, iban text, plan text);
INSERT INTO customers (name, email, iban, plan) VALUES
  ('Customer 001 GmbH', 'billing001@customer.example', 'DE8937040044053200000001', 'standard'),
  ('Customer 002 GmbH', 'billing002@customer.example', 'DE8937040044053200000002', 'trial'),
  ('Customer 003 GmbH', 'billing003@customer.example', 'DE8937040044053200000003', 'enterprise'),
  ('Customer 004 GmbH', 'billing004@customer.example', 'DE8937040044053200000004', 'standard'),
  ('Customer 005 GmbH', 'billing005@customer.example', 'DE8937040044053200000005', 'trial'),
  ('Customer 006 GmbH', 'billing006@customer.example', 'DE8937040044053200000006', 'enterprise'),
  ('Customer 007 GmbH', 'billing007@customer.example', 'DE8937040044053200000007', 'standard'),
  ('Customer 008 GmbH', 'billing008@customer.example', 'DE8937040044053200000008', 'trial'),
  ('Customer 009 GmbH', 'billing009@customer.example', 'DE8937040044053200000009', 'enterprise'),
  ('Customer 010 GmbH', 'billing010@customer.example', 'DE8937040044053200000010', 'standard'),
  ('Customer 011 GmbH', 'billing011@customer.example', 'DE8937040044053200000011', 'trial'),
  ('Customer 012 GmbH', 'billing012@customer.example', 'DE8937040044053200000012', 'enterprise'),
  ('Customer 013 GmbH', 'billing013@customer.example', 'DE8937040044053200000013', 'standard'),
  ('Customer 014 GmbH', 'billing014@customer.example', 'DE8937040044053200000014', 'trial'),
  ('Customer 015 GmbH', 'billing015@customer.example', 'DE8937040044053200000015', 'enterprise'),
  ('Customer 016 GmbH', 'billing016@customer.example', 'DE8937040044053200000016', 'standard'),
  ('Customer 017 GmbH', 'billing017@customer.example', 'DE8937040044053200000017', 'trial'),
  ('Customer 018 GmbH', 'billing018@customer.example', 'DE8937040044053200000018', 'enterprise'),
  ('Customer 019 GmbH', 'billing019@customer.example', 'DE8937040044053200000019', 'standard'),
  ('Customer 020 GmbH', 'billing020@customer.example', 'DE8937040044053200000020', 'trial'),
  ('Customer 021 GmbH', 'billing021@customer.example', 'DE8937040044053200000021', 'enterprise'),
  ('Customer 022 GmbH', 'billing022@customer.example', 'DE8937040044053200000022', 'standard'),
  ('Customer 023 GmbH', 'billing023@customer.example', 'DE8937040044053200000023', 'trial'),
  ('Customer 024 GmbH', 'billing024@customer.example', 'DE8937040044053200000024', 'enterprise'),
  ('Customer 025 GmbH', 'billing025@customer.example', 'DE8937040044053200000025', 'standard');
