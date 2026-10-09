-- 009_discovery_rule_catalogs.sql
--
-- Lets a workspace tune the detection patterns without a code change.
--
-- WHY. Every pattern the scanner matches on lived in DefaultRuleCatalog() in Go:
-- the path globs, the framework vocabulary, the CI action markers. A customer
-- who adopts an agent action we have never heard of, or who names their agent
-- manifests something other than agent.json, had no way to be seen by discovery
-- until someone shipped a release. That is the wrong loop for a detection
-- catalogue, which changes on the customer's timescale rather than ours.
--
-- WHAT IS STORED IS AN OVERLAY, NOT A REPLACEMENT. The row holds add/remove
-- deltas against the built-in catalogue, never a full copy of it. That
-- distinction is the whole design:
--
--   * A workspace that adds one action marker still receives every marker we
--     ship in later releases. Had we stored the full list, customising once
--     would freeze that workspace on the vocabulary of the day they edited, and
--     they would silently stop benefiting from the catalogue improving —
--     the worst kind of regression, because nothing appears to break.
--   * Reset is deleting the row. There is no way for a workspace to edit itself
--     into a state it cannot recover from.
--
-- WHAT IS DELIBERATELY NOT CONFIGURABLE: the extractors. Each rule is parsed by
-- real code that understands a specific format — workflow YAML, compose, a
-- Dockerfile, go.mod. Config selects an extractor BY NAME from a fixed registry;
-- it cannot introduce a new parser. A custom rule pointing a new glob at an
-- existing extractor is supported and is the common case; a genuinely new file
-- FORMAT still needs a release. The alternative — an expression language
-- evaluated over untrusted config against untrusted repository content — is a
-- sandbox escape waiting to happen, for a need nobody has yet.
--
-- STALENESS. Findings record the catalogue version that produced them. Editing
-- this row changes that version, so earlier findings become identifiably "found
-- by an older ruleset" rather than being silently taken as current. Raw file
-- bodies are discarded after parse, so a changed rule CANNOT be replayed over
-- stored evidence — re-deriving requires a rescan, and the API says so.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction.

CREATE TABLE IF NOT EXISTS public.discovery_rule_catalogs (
    -- One overlay per workspace. The workspace IS the key: a second row would
    -- mean two answers to "what does this workspace search for".
    workspace_id uuid PRIMARY KEY,

    -- The overlay: {"vocabularies":{...},"rules":{...},"custom_rules":[...]}.
    -- Shape and limits are enforced in Go before write; see
    -- services/iga_rule_catalog_config.go.
    overlay jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Version of the built-in catalogue this overlay was authored against.
    -- Kept so that a later built-in change that conflicts with an overlay can be
    -- reported to the customer instead of quietly resolved.
    based_on text NOT NULL DEFAULT '',

    -- Content hash of the overlay, recomputed on write. Combined with the
    -- built-in version it forms the effective catalogue version stamped onto
    -- every finding.
    overlay_hash text NOT NULL DEFAULT '',

    updated_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
