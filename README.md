# Customer Management System — Phase 5.3

এই সংস্করণে Phase 5.2-এর সব সুবিধার সাথে Dynamic Customer Form এবং Order Document System যোগ করা হয়েছে।

## নতুন সুবিধা
- Admin/Manager প্রতিটি Service/Post-এর জন্য Customer Form/Box তৈরি করতে পারবেন।
- Text Box, বড় Text Box, Number, Date, Dropdown, Checkbox ও File Upload field যোগ করা যায়।
- কোনো field না দিলে Customer শুধু একটি সাধারণ Description box পাবে।
- Customer-এর Description, নির্দিষ্ট Form তথ্য ও File upload—সবই optional, যদি Admin field-কে Required না করেন।
- Customer Order-এর সাথে সর্বোচ্চ 10টি file, প্রতিটি সর্বোচ্চ 50MB upload করতে পারবে।
- Admin/Manager Pending Order-এর ভিতর file upload করতে পারবেন।
- Confirm & Deduct চাপলে নির্বাচিত Admin/Manager files আগে upload হয়ে তারপর Order confirm হবে।
- Order-এর file authenticated View/Download করা যায়।
- Admin Service Delete করতে পারবেন; Manager পারবেন না।
- Admin/Manager Customer aggregate funds, spent ও remaining balance দেখতে পারবেন।

## Run
```bash
npm install
npm run dev
```
Open: http://localhost:3000

Admin: `admin` / `admin123`
Manager: `manager` / `manager123`
