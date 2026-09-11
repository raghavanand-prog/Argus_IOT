.PHONY: install test api console dev seed evaluate clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -q --upgrade pip
	.venv/bin/pip install -q -e ".[dev]"
	cd console && npm install

test:
	.venv/bin/python -m pytest tests/ -v

api:
	.venv/bin/uvicorn argus.api.main:app --reload --port 8000

console:
	cd console && npm run dev

seed:
	.venv/bin/python -c "from argus.db.models import make_engine, init_db; from argus.pipeline import run_demo_pipeline; e=make_engine(); S=init_db(e); print(run_demo_pipeline(S()))"

evaluate:
	.venv/bin/python -m eval.harness

clean:
	rm -f argus.db
	rm -rf results/
