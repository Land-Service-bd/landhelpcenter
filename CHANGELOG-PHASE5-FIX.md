# Phase 5 Fixes

1. Customer registration now displays the generated unique Customer ID immediately and the ID is always shown on the customer dashboard/profile.
2. Admin can edit service title, description, paid/free status, price/rate, and delete/deactivate services.
3. Manager can edit service title, description, paid/free status, and price/rate, but has no delete/deactivate control and the backend rejects delete requests from Manager.
4. Admin and Manager staff dashboards show aggregate customer finances instead of their own staff balance:
   - Total Customer Funds = approved customer top-ups
   - Total Spent by Customers = approved paid customer orders
   - Current Customer Balance = sum of all current customer balances
5. Staff accounts are excluded from these customer aggregates.
6. Customer order approval still deducts the order amount exactly once because only PENDING orders can be approved.
