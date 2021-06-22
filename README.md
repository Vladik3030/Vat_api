# Vat_api
 Test_task

Hi, this is my variation of API which based on UK validation VAT API, all of that were done in PyCharm

But if you want to start it by console first of all you need to call command

pip install -r requrements.txt

This will install all needed libs for that project.

All of routes where tested in postman and better to use for all of the routes 

There are 9 routes

route('/user', methods=['GET']) with token will return you all of users which are located in Users.db

You can choose one of users by route ('/user/<public_key>', methods=['GET'])

If we want to add new users we can call ('/user', methods=['POST']) with custom information for every new user. All users have string name and password. 

Example of adding in the postman method=['POST'] url="http://127.0.0.1:5000/user" Body[raw]={"name": "Admin", "password": "admin"} (already created user with admin permissions)

All of users creating by default without admin permissions we can give it by route('/user/<public_key>', mehtods=['PUT'])

And for all of users we can recieve token with help of route('/login') in postman we need to choose "Basic Auth" type and enter user username and password.

route('/supported_coutries/cases'. methods=['GET']) whill return countries which are supported in this API

route('/examples', methods=['GET']) will return examples of valid and notValid fiscal numbers, which we can use in route('/fiscal-number-information/<string:coutry>/<string:vat>', methods=['GET']) will return json with information about inputed fiscal number

to call in terminal need to use curl -H "Bearer : your_token which was recieved by /login route" -X GET "http://127.0.0.1:5000/fiscal-number-information/<string:coutry>/<string:vat>, where (Country is GB or whatever and vat is vat number"

