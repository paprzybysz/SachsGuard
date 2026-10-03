"""In-memory demo bank — MCP tool implementations behind Aegis."""

from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Any

# Synthetic Polish retail data for the jury demo. Not real customers.
_SEED_ACCOUNTS: dict[str, dict[str, Any]] = {
    "1001": {
        "account_id": "1001",
        "holder": "Anna Kowalska",
        "iban": "PL61109010140000071219812874",
        "pesel": "44051401359",
        "balance_pln": 42_150.55,
        "currency": "PLN",
        "tenant": "default",
    },
    "1002": {
        "account_id": "1002",
        "holder": "Piotr Nowak",
        "iban": "PL27114020040000300201355387",
        "pesel": "92071304516",
        "balance_pln": 8_040.00,
        "currency": "PLN",
        "tenant": "default",
    },
}

_SEED_COUNTERPARTIES: dict[str, dict[str, Any]] = {
    "44": {
        "counterparty_id": "44",
        "name": "ACME Sp. z o.o.",
        "iban": "PL61109010140000071219812874",
        "balance_pln": 1_250_000.00,
        "kyc": "internal",
    },
    "99": {
        "counterparty_id": "99",
        "name": "Nordic Supplies AB",
        "iban": "SE3550000000054910000003",
        "balance_pln": 88_200.00,
        "kyc": "internal",
    },
}

_SEED_CRM = {
    "T-100": {
        "ticket_id": "T-100",
        "customer": "Anna Kowalska",
        "pesel": "44051401359",
        "summary": "KYC refresh — counterparty 44 wire delay",
        "iban": "PL61109010140000071219812874",
    }
}

_ROLE_ACCOUNT = {"teller": "1001", "admin": "1001", "security": "1001"}


class BankError(ValueError):
    """Unknown tool or invalid arguments."""


class BankTools:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._accounts = deepcopy(_SEED_ACCOUNTS)
            self._counterparties = deepcopy(_SEED_COUNTERPARTIES)
            self._crm = deepcopy(_SEED_CRM)
            self._ledger: list[dict[str, Any]] = [
                {
                    "id": "tx-1",
                    "account_id": "1001",
                    "amount_pln": -120.00,
                    "description": "Card payment — grocery",
                },
                {
                    "id": "tx-2",
                    "account_id": "1001",
                    "amount_pln": 3500.00,
                    "description": "Salary",
                },
            ]
            self._payments: list[dict[str, Any]] = []
            self._github: list[dict[str, Any]] = []
            self._seq = 0

    @property
    def payment_count(self) -> int:
        with self._lock:
            return len(self._payments)

    def dispatch(self, tool_name: str, arguments: dict[str, Any], *, role: str, tenant: str) -> dict[str, Any]:
        handlers = {
            "echo": self._echo,
            "get_account_balance": self._get_account_balance,
            "get_counterparty_balance": self._get_counterparty_balance,
            "list_transactions": self._list_transactions,
            "initiate_payment": self._initiate_payment,
            "get_ticket_from_crm": self._get_ticket_from_crm,
            "file_github_issue": self._file_github_issue,
            "send_email": self._send_email,
            "calculator": self._calculator,
            "search": self._search,
            "get_weather": self._weather,
            "list_files": self._list_files,
            "read_file": self._read_file,
        }
        fn = handlers.get(tool_name)
        if fn is None:
            raise BankError(f"unknown bank tool: {tool_name}")
        with self._lock:
            return fn(arguments or {}, role=role, tenant=tenant)

    def _echo(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        return {"echo": arguments}

    def _get_account_balance(self, arguments: dict[str, Any], *, role: str, tenant: str) -> dict[str, Any]:
        account_id = str(arguments.get("account_id") or _ROLE_ACCOUNT.get(role) or "1001")
        account = self._accounts.get(account_id)
        if account is None or account.get("tenant") != tenant:
            raise BankError("account not found")
        return {
            "account_id": account["account_id"],
            "holder": account["holder"],
            "iban": account["iban"],
            "balance_pln": account["balance_pln"],
            "currency": account["currency"],
        }

    def _get_counterparty_balance(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        cid = str(arguments.get("counterparty_id") or arguments.get("id") or "")
        row = self._counterparties.get(cid)
        if row is None:
            raise BankError("counterparty not found")
        return dict(row)

    def _list_transactions(self, arguments: dict[str, Any], *, role: str, tenant: str) -> dict[str, Any]:
        account_id = str(arguments.get("account_id") or _ROLE_ACCOUNT.get(role) or "1001")
        txs = [t for t in self._ledger if t["account_id"] == account_id]
        return {"account_id": account_id, "transactions": txs}

    def _initiate_payment(self, arguments: dict[str, Any], *, role: str, tenant: str) -> dict[str, Any]:
        self._seq += 1
        src = str(arguments.get("from_account") or _ROLE_ACCOUNT.get(role) or "1001")
        amount = float(arguments.get("amount_pln") or arguments.get("amount") or 0)
        dest = str(arguments.get("to_iban") or arguments.get("iban") or "")
        account = self._accounts.get(src)
        if account is None or account.get("tenant") != tenant:
            raise BankError("source account not found")
        if amount <= 0:
            raise BankError("amount must be positive")
        if account["balance_pln"] < amount:
            raise BankError("insufficient funds")
        account["balance_pln"] = round(account["balance_pln"] - amount, 2)
        payment = {
            "payment_id": f"pay-{self._seq}",
            "from_account": src,
            "to_iban": dest,
            "amount_pln": amount,
            "status": "executed",
            "ts": time.time(),
        }
        self._payments.append(payment)
        self._ledger.append(
            {
                "id": payment["payment_id"],
                "account_id": src,
                "amount_pln": -amount,
                "description": f"Transfer to {dest}",
            }
        )
        return payment

    def _get_ticket_from_crm(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        tid = str(arguments.get("ticket_id") or "T-100")
        ticket = self._crm.get(tid)
        if ticket is None:
            raise BankError("ticket not found")
        return dict(ticket)

    def _file_github_issue(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        issue = {
            "title": arguments.get("title") or "untitled",
            "body": arguments.get("body") or arguments.get("content") or "",
            "ts": time.time(),
        }
        self._github.append(issue)
        return {"ok": True, "issue": issue}

    def _send_email(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        return {"ok": True, "to": arguments.get("to"), "subject": arguments.get("subject")}

    def _calculator(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        return {"echo": arguments, "result": arguments.get("expression") or arguments}

    def _search(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        return {"hits": [], "query": arguments.get("query")}

    def _weather(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        return {"location": arguments.get("location") or "Warsaw", "summary": "Cloudy, 14C"}

    def _list_files(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        return {"files": ["public-docs/faq.md", "marketing/offer.pdf"]}

    def _read_file(self, arguments: dict[str, Any], **_: Any) -> dict[str, Any]:
        path = str(arguments.get("path") or "")
        if "customer-records" in path or "kyc" in path:
            return {"path": path, "content": "KYC pack — PESEL 44051401359 IBAN PL61109010140000071219812874"}
        return {"path": path, "content": "public FAQ"}


BANK = BankTools()
