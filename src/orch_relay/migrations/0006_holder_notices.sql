-- Digest of the notices last delivered to the current holder generation (NULL: none yet,
-- equivalent to empty notices). Host polls are ready on items or a changed digest only.
ALTER TABLE holder_delivery ADD COLUMN notices TEXT;
