1) Create JWT Token for first time getting from client call
   http://localhost:8080/token, Method : Post
   Request Body :
   {
      "username":"ram",
      "password":"password"
   }
   Response IS:
   {
   "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyYW0iLCJleHAiOjE2ODU3MzY0NDYsImlhdCI6MTY4NTcwMDQ0Nn0.jyCl5j3BEo4PWTofT4bk5ikV8dkpt5NAY88ZRj5RyD0"
   }
2) Call to resources
   http://localhost:8080/hello/admin
   Method : GET
   Authorization : Bearer Auth Token
