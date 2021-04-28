package com.edafa;

import org.mindrot.jbcrypt.BCrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Objects;

public class UserHandler {
    private static String passwdFileName="src/main/resources/jsonpasswd.json";

    public static HashMap<String, String> handShake(PrintWriter output, BufferedReader input) throws IOException {

        boolean newFlag=false;
        HashMap<String,String> userIn=getUserCred(input,output);


        //System.out.println(userIn);
        if (userIn.get("newFlag")!=null){newFlag=true;}
        while (!checkAuth(userIn.get("user"),userIn.get("pass"),newFlag)){
            output.println("Invalid UserName or Password,Tap Enter to login again");
            newFlag=false;
            input.readLine();
            userIn=UserHandler.getUserCred(input,output);
        }
        output.println("success");
        return userIn;
    }

    private static HashMap<String, String> getUserCred(BufferedReader input, PrintWriter output) {
        HashMap<String,String> userCred=new HashMap<>();

        boolean newUserFlag=false;
        String stringToShow="Please Enter User Name or just n for a new user: ";

        while (true){
            output.println(stringToShow);

            try {
                String resp=input.readLine();
                if (resp.equals("n")){
                    newUserFlag=true;
                    stringToShow="Please Enter Your User Name";
                    continue;
                }
                userCred.put("user",resp);
            } catch (IOException e) {
                output.println("Wrong Input");
                continue;
            }

            output.println("Please Enter Password: ");

            try {
                userCred.put("pass",input.readLine());
            } catch (IOException e) {
                output.println("Wrong Input");
                continue;
            }

            if (newUserFlag){
                    createNewUser(userCred);
                    userCred.put("newFlag","true");
                }

            return userCred;
        }
    }

    public static void createNewUser(HashMap<String,String> userData){
        String hashed;
        StringBuilder stringBuilder=FileHandler.readFile(passwdFileName);
        assert stringBuilder != null;
        HashMap<String,String> allUsers=FileHandler.getJsonMap(stringBuilder);

        hashed = BCrypt.hashpw(userData.get("pass"), BCrypt.gensalt());
        assert allUsers != null;
        allUsers.put(userData.get("user"),hashed);
        FileHandler.writeJson(allUsers,passwdFileName);
    }


    public static boolean checkAuth(String userName,String pass,boolean newFlag) {
        HashMap<String, String> map = FileHandler.getJsonMap(Objects.requireNonNull(FileHandler.readFile(passwdFileName)));
        if (newFlag) {
            if (map.get(userName) != null) {
                   // user already exists
            }
            }
        else {
            assert map != null;
            if (map.get(userName) != null) {
                    System.out.println(map.get(userName));
                    return BCrypt.checkpw(pass, map.get(userName));
                }
        }

            return false;


    }
    }



