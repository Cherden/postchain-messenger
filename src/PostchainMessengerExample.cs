using Postchain.Examples.Messenger;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Chromia.PostchainClient;
using Chromia.PostchainClient.GTX;

class PostchainMessengerExample
{
    const string blockchainRIDTerminal = "78967BAA4768CBCEF11C508326FFB13A956689FCB6DC3BA17F4B895CBB1577A3";
    const string blockchainRIDEclipse = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    private static RESTClient restClient;
    private static GTXClient gtxClient;
    private static byte[] gtxPrivateKey;
    private static byte[] gtxPublicKey;
    private static bool running = true;
    private static bool userCreated = false;

    private static PostchainMessenger messenger;

    public static void Main()
    {
        var keyPair = Util.MakeKeyPair();
        gtxPrivateKey = keyPair["privKey"];
        gtxPublicKey = keyPair["pubKey"];
        restClient = new RESTClient("http://localhost:7740", blockchainRIDEclipse);        
        gtxClient = new GTXClient(restClient, blockchainRIDEclipse);

        Console.WriteLine("Usage:");
        Console.WriteLine("/c:\tCreate a user");
        Console.WriteLine("/sf:\tSend friend request to user");
        Console.WriteLine("/af:\tAccept friend request from user");
        Console.WriteLine("/s:\tSend message to user");

        messenger = new PostchainMessenger(gtxClient, keyPair["privKey"], keyPair["pubKey"]);

        Task.Run(async () =>
            {
                while (running)
                {
                    if (userCreated)
                    {
                        List<string> newFriendRequests = await messenger.GetFriendRequests();
                        foreach (string friendRequestName in newFriendRequests)
                        {
                            Console.WriteLine("New friend request from " + friendRequestName);
                        }

                        List<Message> newMessages = await messenger.GetNewMessages();
                        foreach (Message message in newMessages)
                        {
                            Console.WriteLine("[" + message.timestamp + "] " + message.sender + ": " + message.content); 
                        }
                    }
                    await Task.Delay(100);
                }
            }
        );

        while (running)
        {
            string input = Console.ReadLine();
            string[] parameters = input.Split(' ');

            if (parameters.Length < 2)
            {
                continue;
            }

            switch (parameters[0])
            {
                case "/c":
                {
                    HandleCreateUser(parameters[1]);
                    break;
                }
                case "/sf":
                {
                    HandleSendFriendRequest(parameters[1]);
                    break;
                }
                case "/af":
                {
                    HandleAcceptFriendRequest(parameters[1]);
                    break;
                }
                case "/s":
                {
                    HandleSendMessage(parameters[1], parameters.Skip(2).Aggregate((acc, str) => acc += " " + str));
                    break;
                }
            }
        }
    }

    public static void HandleCreateUser(string new_name)
    {
        CreateUser(new_name);
        Thread.Sleep(2000);
        userCreated = true;
    }

    public static void HandleSendFriendRequest(string name)
    {
        messenger.SendFriendRequest(name);
    }

    public static void HandleAcceptFriendRequest(string name)
    {
        messenger.AcceptFriendRequest(name);
    }

    public static void HandleSendMessage(string name, string message)
    {        
        messenger.SendMessage(name, message);
    }

    public static async void CreateUser(string name)
    {
        Transaction tx = gtxClient.NewTransaction(new byte[][] {gtxPublicKey});
        tx.AddOperation("create_user", name, gtxPublicKey);
        tx.Sign(gtxPrivateKey, gtxPublicKey);
        await tx.PostAndWaitConfirmation();
    }
}