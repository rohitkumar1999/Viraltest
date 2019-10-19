package com.example.viraltest;

import android.app.Service;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Scanner;

public class SendDataService extends Service {
    private final LocalBinder mBinder = new LocalBinder();
    protected Handler handler;
    protected Toast mToast;

    public class LocalBinder extends Binder {
        public SendDataService getService() {
            return SendDataService .this;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public void onCreate() {
        super.onCreate();

    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        Intent intent = new Intent("com.android.ServiceStopped");
        sendBroadcast(intent);
    }
    public static boolean isValid(String url)
    {
        /* Try creating a valid URL */
        try {
            new URL(url).toURI();
            return true;
        }

        // If there was an Exception
        // while creating URL object
        catch (Exception e) {
            return false;
        }
    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        handler = new Handler();
        handler.post(new Runnable() {
            @Override
            public void run() {
               final ClipboardManager clipBoard = (ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
                clipBoard.addPrimaryClipChangedListener(new ClipboardManager.OnPrimaryClipChangedListener() {

                    @Override
                    public void onPrimaryClipChanged() {
                        ClipData clipData = clipBoard.getPrimaryClip();
                        ClipData.Item item = clipData.getItemAt(0);
                        String str = item.getText().toString();
                        Log.d("main","Clipboard"+str) ;
                            NetworkTask networkTask = new NetworkTask(getApplicationContext());
                            networkTask.execute("https://www.virustotal.com/vtapi/v2/url/report?" +
                                    "apikey=38523c6bc6ad41e2da03f189151c61e7d03142b0bc485985977d1a776fa19ac4" +
                                    "&resource=" + str);




                    }
                });
            }
        });
        return android.app.Service.START_STICKY;
    }

}
class NetworkTask extends AsyncTask<String,Void,String>
{
    private Context mContext ;

    public NetworkTask(Context context) {
    mContext = context ;

    }

    @Override
    protected void onPostExecute(String s) {
        super.onPostExecute(s);
        Log.d("main", "ONPOSTEXECUTE");

        ArrayList<details> users = jsonparser(s);
//        Log.d("main", users.get(0).getPositives());
        if(Integer.parseInt(users.get(0).getResponse_code())==0)
            Toast.makeText(mContext,"Sorry no record found", Toast.LENGTH_SHORT).show();
        else  if(Integer.parseInt(users.get(0).getResponse_code())==1)
        {
            if(Integer.parseInt(users.get(0).getPositives())==0)
                Toast.makeText(mContext,"URL is clean", Toast.LENGTH_SHORT).show();
            else
                Toast.makeText(mContext,"Malware found dangerous", Toast.LENGTH_SHORT).show();



        }



    }


    @Override
    protected String doInBackground(String... strings) {
        String url1 = strings[0] ;
        Log.d("main","DOINBACKGROUND") ;
        try {
            URL url = new URL(url1) ;
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection() ;
            InputStream inputStream = httpURLConnection.getInputStream() ;
            Scanner scanner = new Scanner(inputStream) ;
            scanner.useDelimiter("\\A") ;
            if(scanner.hasNext())
            {
                String s = scanner.next() ;
                Log.d("main","DOINBACKGROUNDEND") ;


                return s ;  }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Log.d("main","DOINBACKGROUNDEND") ;


        return "Failed to load " ;
    }


    private ArrayList<details> jsonparser(String s) {
        ArrayList<details> list = new ArrayList<>() ;
        Log.d("main","JSONPARSER") ;

        try {
            JSONObject object = new JSONObject(s) ;
            String response_code = object.getString("response_code")  ;
            String positives = object.getString("positives") ;
            String total = object.getString("total") ;
            Log.d("tag", positives+" "+total);
            details githubUser = new details(response_code,positives,total) ;
            list.add(githubUser) ;

        } catch (JSONException e) {
            e.printStackTrace();
        }
        Log.d("main","JSONPARSER"+list.size()) ;
        return list ;
    }
}
