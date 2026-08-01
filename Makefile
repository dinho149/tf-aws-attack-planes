# tf-aws-attack-planes - task runner
#
# A thin, visible wrapper over `terraform`, ./scripts/simulate-attack.sh and the
# mcp-server venv. Nothing is hidden: every recipe echoes or runs the real command,
# so you can always drop back to the raw tool.
#
# Quick start:
#   make preflight        # is this machine ready?
#   make tfvars           # bootstrap terraform.tfvars from the example
#   make deploy_1         # stand up scenario 1
#   make scenario_1       # fire its attack
#   make athena           # open the console to investigate
#   make destroy          # tear it all down
#
# Written for GNU Make 3.81 (the version macOS ships): no .ONESHELL, no $(file),
# no .RECIPEPREFIX. Multi-step recipes are single backslash-continued POSIX sh lines.

# ---------------------------------------------------------------------------------
# Tunables - override on the command line, e.g. `make apply REGION=eu-west-1 AUTO=1`
# ---------------------------------------------------------------------------------
TF          ?= terraform
PYTHON      ?= python3
SCENARIOS   := 1 2 3 4 5

REGION      ?=
PROFILE     ?=
AUTO        ?=
ONLY        ?=
CONFIRM     ?=
N           ?= 1
I           ?= 0
ARGS        ?=
OUT         ?=
TF_ARGS     ?=
PYTEST_ARGS ?=
TFLINT_STRICT ?=

MCP_NAME    ?= aws-audit-planes
MCP_SCOPE   ?= local

# ---------------------------------------------------------------------------------
# Derived
# ---------------------------------------------------------------------------------
SIM           := ./scripts/simulate-attack.sh
MCP_DIR       := mcp-server
VENV          := $(MCP_DIR)/.venv
VENV_ABS      := $(abspath $(VENV))
MCP_BIN       := $(VENV)/bin/aws-audit-planes-mcp
MCP_BIN_ABS   := $(abspath $(MCP_BIN))
TF_INIT_STAMP := .terraform/.make-init-stamp

# AUTO=0 / AUTO=no must NOT be truthy, so match an explicit allow-list.
APPROVE         := $(if $(filter 1 y yes true YES TRUE,$(AUTO)),-auto-approve,)
EXCLUSIVE       := $(filter 1 y yes true YES TRUE,$(ONLY))
TF_REGION       := $(if $(strip $(REGION)),-var region=$(strip $(REGION)),)
TF_FLAGS        := $(TF_REGION) $(TF_ARGS)
SIM_REGION      := $(if $(strip $(REGION)),-r $(strip $(REGION)),)
AWS_REGION_FLAG := $(if $(strip $(REGION)),--region $(strip $(REGION)),)

ifneq ($(strip $(PROFILE)),)
export AWS_PROFILE := $(strip $(PROFILE))
endif

.DEFAULT_GOAL := help
.NOTPARALLEL:            # one AWS estate, one local state file - never interleave
.DELETE_ON_ERROR:        # a half-installed venv must not look up to date

# ---------------------------------------------------------------------------------
##@ Help
# ---------------------------------------------------------------------------------

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} \
	     /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
	     /^[a-zA-Z0-9_%-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)
	@printf '\n\033[1mVariables\033[0m\n'
	@printf '  \033[36m%-14s\033[0m %s\n' \
	  REGION  'AWS region (default: var.region)' \
	  PROFILE 'AWS profile, exported as AWS_PROFILE' \
	  AUTO    'AUTO=1 -> terraform -auto-approve' \
	  ONLY    'ONLY=1 -> deploy_N disables the other four scenarios' \
	  CONFIRM 'CONFIRM=destroy -> skip the typed destroy guard' \
	  N       'simulate-attack.sh --count (default 1)' \
	  I       'simulate-attack.sh --interval seconds (default 0)' \
	  ARGS    'extra flags for simulate-attack.sh, e.g. ARGS=--no-reset' \
	  OUT     'make outputs OUT=log_bucket -> one raw value' \
	  TF_ARGS 'extra flags for terraform'
	@printf '\n\033[1mExamples\033[0m\n'
	@printf '  make deploy_3 REGION=eu-west-1\n'
	@printf '  make scenario_2 N=5 I=60\n'
	@printf '  make scenario_1 ARGS=--no-reset\n'
	@printf '  make destroy AUTO=1 CONFIRM=destroy   # non-interactive teardown\n\n'

preflight: ## Check terraform/aws/python3/jq and your AWS credentials
	@ok=1; \
	echo "== required =="; \
	for t in $(TF) aws; do \
	  if command -v $$t >/dev/null 2>&1; then \
	    echo "  [ ok ] $$t -> $$(command -v $$t)"; \
	  else echo "  [MISS] $$t (required)"; ok=0; fi; \
	done; \
	if command -v $(PYTHON) >/dev/null 2>&1; then \
	  if $(PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then \
	    echo "  [ ok ] $(PYTHON) -> $$($(PYTHON) -V 2>&1)"; \
	  else \
	    echo "  [MISS] $(PYTHON) is $$($(PYTHON) -V 2>&1) - the MCP server needs >= 3.12"; ok=0; \
	  fi; \
	else echo "  [MISS] $(PYTHON) (required for the MCP server)"; ok=0; fi; \
	echo "== optional =="; \
	for t in jq tflint shellcheck; do \
	  if command -v $$t >/dev/null 2>&1; then \
	    echo "  [ ok ] $$t -> $$(command -v $$t)"; \
	  else echo "  [warn] $$t (optional)"; fi; \
	done; \
	echo "== aws credentials =="; \
	if id="$$(aws sts get-caller-identity $(AWS_REGION_FLAG) --output text \
	          --query '[Account,Arn]' 2>&1)"; then \
	  echo "  [ ok ] $$id"; \
	else \
	  echo "  [MISS] aws sts get-caller-identity failed:"; echo "         $$id"; ok=0; \
	fi; \
	echo ""; \
	if [ "$$ok" -ne 1 ]; then echo "preflight: FAILED" >&2; exit 1; fi; \
	echo "preflight: ok - note this repo applies a deliberately-vulnerable estate."; \
	echo "           Use a throwaway sandbox account only."

# ---------------------------------------------------------------------------------
##@ Terraform
# ---------------------------------------------------------------------------------

tfvars: ## Create terraform.tfvars from the example (never overwrites)
	@if [ -e terraform.tfvars ]; then \
	  echo "terraform.tfvars already exists - leaving it alone."; \
	  echo "(remove it yourself if you really want to re-bootstrap)"; \
	else \
	  cp terraform.tfvars.example terraform.tfvars && \
	  echo "created terraform.tfvars from the example - now set alert_email etc."; \
	fi

# Gate init on a stamp we own, inside the already-gitignored .terraform/.
$(TF_INIT_STAMP): main.tf versions.tf providers.tf .terraform.lock.hcl
	$(TF) init -input=false
	@touch $@

init: ## terraform init
	$(TF) init -input=false
	@touch $(TF_INIT_STAMP)

reinit: ## terraform init -upgrade (re-resolve providers)
	$(TF) init -input=false -upgrade
	@touch $(TF_INIT_STAMP)

plan: | $(TF_INIT_STAMP) ## terraform plan
	$(TF) plan $(TF_FLAGS)

apply: | $(TF_INIT_STAMP) ## terraform apply (prompts; AUTO=1 to skip)
	$(TF) apply $(TF_FLAGS) $(APPROVE)

destroy: | $(TF_INIT_STAMP) ## terraform destroy (typed confirmation, then terraform's own)
	@if [ "$(CONFIRM)" = "destroy" ]; then \
	  echo ">> CONFIRM=destroy given - skipping the typed guard"; \
	else \
	  echo ""; \
	  echo "  This DESTROYS the whole tf-aws-attack-planes estate in:"; \
	  echo "    account : $$(aws sts get-caller-identity $(AWS_REGION_FLAG) \
	                         --query Account --output text 2>/dev/null || echo '<unknown>')"; \
	  reg="$$($(TF) output -raw region 2>/dev/null)"; \
	  echo "    region  : $${reg:-<no state - nothing to destroy?>}"; \
	  echo "  including the log bucket and everything it has collected."; \
	  echo ""; \
	  printf '  Type "destroy" to confirm: '; \
	  read -r ans || { echo ""; echo "aborted (no tty - use CONFIRM=destroy)" >&2; exit 1; }; \
	  if [ "$$ans" != "destroy" ]; then echo "aborted." >&2; exit 1; fi; \
	fi; \
	$(TF) destroy $(TF_FLAGS) $(APPROVE)

outputs: ## Print terraform outputs (OUT=name for a single raw value)
	@if [ -n "$(strip $(OUT))" ]; then \
	  $(TF) output -raw $(strip $(OUT)); echo ""; \
	else \
	  $(TF) output; \
	fi

athena: ## Open the Athena console for this deployment
	@url="$$($(TF) output -raw athena_console_url 2>/dev/null)"; \
	if [ -z "$$url" ]; then \
	  echo "no athena_console_url output - has this been applied? (try: make apply)" >&2; \
	  exit 1; \
	fi; \
	echo "$$url"; \
	if command -v open >/dev/null 2>&1; then open "$$url"; \
	elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$$url"; \
	else echo "(no opener found - copy the URL above)"; fi

fmt: ## terraform fmt -recursive (rewrites files)
	$(TF) fmt -recursive

validate: | $(TF_INIT_STAMP) ## terraform validate
	$(TF) validate

lint: validate ## fmt -check + validate (hard gates), plus tflint/shellcheck when installed
	$(TF) fmt -check -recursive
	@if command -v shellcheck >/dev/null 2>&1; then \
	  echo ">> shellcheck $(SIM)"; shellcheck $(SIM); \
	else echo ">> shellcheck not installed - skipping"; fi
	@if command -v tflint >/dev/null 2>&1; then \
	  echo ">> tflint --recursive"; \
	  if tflint --recursive; then :; \
	  elif [ -n "$(strip $(TFLINT_STRICT))" ]; then \
	    echo ">> tflint reported issues and TFLINT_STRICT is set - failing" >&2; exit 1; \
	  else \
	    echo ""; \
	    echo ">> tflint reported issues (advisory - these are pre-existing module-level"; \
	    echo "   style warnings, not a regression). Run 'make lint TFLINT_STRICT=1' to"; \
	    echo "   make them fatal once they are cleaned up."; \
	  fi; \
	else echo ">> tflint not installed - skipping"; fi

# ---------------------------------------------------------------------------------
##@ Scenarios - deploy
# ---------------------------------------------------------------------------------

# Pattern rules cannot be .PHONY: GNU make skips implicit-rule search for phony
# targets, so `.PHONY: deploy_1` would make `make deploy_1` a no-op. FORCE keeps
# deploy_%/scenario_% permanently out of date instead. Do NOT add them to .PHONY.
.PHONY: FORCE
FORCE:

deploy_%: FORCE | $(TF_INIT_STAMP) ## Deploy one scenario: deploy_1 .. deploy_5
	@case " $(SCENARIOS) " in \
	  *" $* "*) ;; \
	  *) echo "make: *** '$@': scenario '$*' is out of range (valid: $(SCENARIOS))" >&2; exit 2;; \
	esac; \
	if [ -n "$(EXCLUSIVE)" ]; then \
	  flags=""; \
	  for s in $(SCENARIOS); do \
	    if [ "$$s" = "$*" ]; then v=true; else v=false; fi; \
	    flags="$$flags -var scenario_0$${s}_enabled=$$v"; \
	  done; \
	  echo ">> deploy scenario $* ONLY - the other four are set false and WILL BE DESTROYED"; \
	else \
	  flags="-var scenario_0$*_enabled=true"; \
	  echo ">> deploy scenario $* (additive - other scenarios stay as terraform.tfvars has them)"; \
	  echo "   read the plan before approving; ONLY=1 deploys scenario $* exclusively"; \
	fi; \
	echo "+ $(TF) apply$$flags $(TF_FLAGS) $(APPROVE)"; \
	$(TF) apply $$flags $(TF_FLAGS) $(APPROVE)

deploy_all: | $(TF_INIT_STAMP) ## Deploy all five scenarios (real spend: ALB, WAF, EC2, data events)
	@flags=""; \
	for s in $(SCENARIOS); do flags="$$flags -var scenario_0$${s}_enabled=true"; done; \
	echo "+ $(TF) apply$$flags $(TF_FLAGS) $(APPROVE)"; \
	$(TF) apply $$flags $(TF_FLAGS) $(APPROVE)

# ---------------------------------------------------------------------------------
##@ Scenarios - fire
# ---------------------------------------------------------------------------------

scenario_%: FORCE ## Fire one scenario's attack: scenario_1 .. scenario_5
	@case " $(SCENARIOS) " in \
	  *" $* "*) ;; \
	  *) echo "make: *** '$@': scenario '$*' is out of range (valid: $(SCENARIOS))" >&2; exit 2;; \
	esac; \
	echo "+ $(SIM) -s $* -n $(N) -i $(I) $(SIM_REGION) $(ARGS)"; \
	$(SIM) -s $* -n $(N) -i $(I) $(SIM_REGION) $(ARGS)

fire_all: ## Fire scenarios 1..5 in sequence
	@for s in $(SCENARIOS); do \
	  echo ""; echo "########## scenario $$s ##########"; \
	  $(MAKE) --no-print-directory scenario_$$s || exit $$?; \
	done

# ---------------------------------------------------------------------------------
##@ MCP server
# ---------------------------------------------------------------------------------

# The console script is both the install sentinel and the binary handed to clients,
# so `make mcp` is a no-op once installed and only re-runs when pyproject.toml changes.
$(MCP_BIN): $(MCP_DIR)/pyproject.toml
	@if [ ! -x "$(VENV)/bin/python" ]; then \
	  echo ">> creating $(VENV) with $(PYTHON)"; \
	  $(PYTHON) -m venv $(VENV); \
	fi
	@$(VENV)/bin/python -m pip install --quiet --upgrade pip
	$(VENV)/bin/python -m pip install -e './$(MCP_DIR)[dev]'
	@touch $@

mcp: $(MCP_BIN) ## Create/refresh mcp-server/.venv and pip install -e '.[dev]'
	@echo "mcp server ready: $(MCP_BIN_ABS)"

mcp-test: $(MCP_BIN) ## Run the MCP server test suite
	cd $(MCP_DIR) && $(VENV_ABS)/bin/pytest $(PYTEST_ARGS)

mcp-dev: $(MCP_BIN) ## Launch the MCP inspector (needs node/npx)
	cd $(MCP_DIR) && $(VENV_ABS)/bin/mcp dev src/audit_planes_mcp/server.py

mcp-run: $(MCP_BIN) ## Run the stdio MCP server in the foreground
	$(MCP_BIN_ABS)

mcp-register: $(MCP_BIN) ## Register the server with Claude Code (claude mcp add)
	@if command -v claude >/dev/null 2>&1; then \
	  claude mcp add $(MCP_NAME) --scope $(MCP_SCOPE) \
	    $(if $(strip $(REGION)),-e AWS_REGION=$(strip $(REGION)),) \
	    $(if $(strip $(PROFILE)),-e AWS_PROFILE=$(strip $(PROFILE)),) \
	    -- $(MCP_BIN_ABS); \
	else \
	  echo "claude CLI not found - add this to your MCP client config by hand:"; \
	  echo ''; \
	  echo '  {'; \
	  echo '    "mcpServers": {'; \
	  echo '      "$(MCP_NAME)": {'; \
	  echo '        "command": "$(MCP_BIN_ABS)",'; \
	  echo '        "env": { "AWS_REGION": "$(if $(strip $(REGION)),$(strip $(REGION)),us-east-1)" }'; \
	  echo '      }'; \
	  echo '    }'; \
	  echo '  }'; \
	  exit 1; \
	fi

# ---------------------------------------------------------------------------------
##@ Housekeeping
# ---------------------------------------------------------------------------------

test: validate mcp-test ## terraform validate + the MCP test suite

clean: ## Remove build/test junk (never touches state, tfvars or the venv)
	@rm -f tfplan tfplan.* crash.log crash.*.log
	@rm -rf $(MCP_DIR)/.pytest_cache $(MCP_DIR)/build $(MCP_DIR)/dist
	@find $(MCP_DIR) -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@find $(MCP_DIR) -name '*.egg-info' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "clean: left terraform.tfstate*, terraform.tfvars, .terraform/ and $(VENV) alone"

distclean: clean ## Also remove .terraform/ and the MCP venv (state and tfvars survive)
	@rm -rf .terraform $(VENV)
	@echo "distclean: removed .terraform/ and $(VENV) - run 'make init' / 'make mcp' to rebuild"
	@echo "           terraform.tfstate* and terraform.tfvars were NOT touched"

.PHONY: help preflight tfvars init reinit plan apply destroy outputs athena fmt \
        validate lint deploy_all fire_all mcp mcp-test mcp-dev mcp-run mcp-register \
        test clean distclean
