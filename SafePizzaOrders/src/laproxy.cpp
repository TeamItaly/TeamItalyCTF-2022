/* 
   Copyright (c) 2007 Arash Partow (http://www.partow.net)
   URL: http://www.partow.net/programming/tcpproxy/index.html
   Modified and adapted by Pwnzer0tt1
*/
#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <string>
#include <mutex>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <jpcre2.hpp>

typedef jpcre2::select<char> jp;
using namespace std;

typedef vector<jp::Regex> regex_rule_vector;
struct regex_rules{
   regex_rule_vector filter;


   void add(string expr){
      jp::Regex regex(expr,"gS");
      if (regex){
         cerr << "Added regex " << expr << endl;
         filter.push_back(regex);
      } else {
         cerr << "Regex " << expr << " was not compiled successfully" << endl;
      }
   }

   bool check(string data){
      for (auto &regex : filter){
         if (regex.match(data)){
            return false;
         }
      }
      return true;
   }
   template <typename T>
   bool check(T *data, size_t len){
      return check(string((char*)data,len));
   }

} regex_config;

namespace tcp_proxy
{
   namespace ip = boost::asio::ip;

   class bridge : public boost::enable_shared_from_this<bridge>
   {
   public:

      typedef ip::tcp::socket socket_type;
      typedef boost::shared_ptr<bridge> ptr_type;

      bridge(boost::asio::io_context& ios)
      : downstream_socket_(ios),
        upstream_socket_  (ios),
        thread_safety(ios)
      {}

      socket_type& downstream_socket()
      {
         // Client socket
         return downstream_socket_;
      }

      socket_type& upstream_socket()
      {
         // Remote server socket
         return upstream_socket_;
      }

      void start(const string& upstream_host, unsigned short upstream_port)
      {
         // Attempt connection to remote server (upstream side)
         upstream_socket_.async_connect(
              ip::tcp::endpoint(
                   boost::asio::ip::address::from_string(upstream_host),
                   upstream_port),
               boost::asio::bind_executor(thread_safety,
               boost::bind(
                  &bridge::handle_upstream_connect,
                    shared_from_this(),
                    boost::asio::placeholders::error)));
      }

      void handle_upstream_connect(const boost::system::error_code& error)
      {
         if (!error)
         {
            // Setup async read from remote server (upstream)
            upstream_socket_.async_read_some(
                 boost::asio::buffer(upstream_data_,max_data_length),
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_upstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));

            // Setup async read from client (downstream)
            downstream_socket_.async_read_some(
                 boost::asio::buffer(downstream_data_,max_data_length),
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_downstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));
         }
         else
            close();
      }

   private:

      /*
         Section A: Remote Server --> Proxy --> Client
         Process data recieved from remote sever then send to client.
      */

      // Read from remote server complete, now send data to client
      void handle_upstream_read(const boost::system::error_code& error,
                                const size_t& bytes_transferred) // Da Server a Client
      {
         if (!error)
         {
            async_write(downstream_socket_,
               boost::asio::buffer(upstream_data_,bytes_transferred),
               boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_downstream_write,
                     shared_from_this(),
                     boost::asio::placeholders::error)));
         }
         else
            close();
      }

      // Write to client complete, Async read from remote server
      void handle_downstream_write(const boost::system::error_code& error)
      {
         if (!error)
         {

            upstream_socket_.async_read_some(
                 boost::asio::buffer(upstream_data_,max_data_length),
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_upstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));
         }
         else
            close();
      }
      // *** End Of Section A ***


      /*
         Section B: Client --> Proxy --> Remove Server
         Process data recieved from client then write to remove server.
      */

      // Read from client complete, now send data to remote server
      void handle_downstream_read(const boost::system::error_code& error,
                                  const size_t& bytes_transferred) // Da Client a Server
      {
         if (!error)
         {
            if (regex_config.check(downstream_data_, bytes_transferred)){
               async_write(upstream_socket_,
                  boost::asio::buffer(downstream_data_,bytes_transferred),
                  boost::asio::bind_executor(thread_safety,
                        boost::bind(&bridge::handle_upstream_write,
                        shared_from_this(),
                        boost::asio::placeholders::error)));
            }else{
               close();
            }
         }
         else
            close();
      }

      // Write to remote server complete, Async read from client
      void handle_upstream_write(const boost::system::error_code& error)
      {
         if (!error)
         {
            downstream_socket_.async_read_some(
                 boost::asio::buffer(downstream_data_,max_data_length),
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_downstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));
         }
         else close();
      }
      // *** End Of Section B ***

      void close()
      {
         boost::mutex::scoped_lock lock(mutex_);

         if (downstream_socket_.is_open())
         {
            downstream_socket_.close();
         }

         if (upstream_socket_.is_open())
         {
            upstream_socket_.close();
         }
      }

      socket_type downstream_socket_;
      socket_type upstream_socket_;

      enum { max_data_length = 8192 }; //8KB
      unsigned char downstream_data_[max_data_length];
      unsigned char upstream_data_  [max_data_length];
      boost::asio::io_context::strand thread_safety;
      boost::mutex mutex_;
   public:

      class acceptor
      {
      public:

         acceptor(boost::asio::io_context& io_context,
                  const string& local_host, unsigned short local_port,
                  const string& upstream_host, unsigned short upstream_port)
         : io_context_(io_context),
           localhost_address(boost::asio::ip::address_v4::from_string(local_host)),
           acceptor_(io_context_,ip::tcp::endpoint(localhost_address,local_port)),
           upstream_port_(upstream_port),
           upstream_host_(upstream_host)
         {}

         bool accept_connections()
         {
            try
            {
               session_ = boost::shared_ptr<bridge>(new bridge(io_context_));

               acceptor_.async_accept(session_->downstream_socket(),
                    boost::asio::bind_executor(session_->thread_safety,
                    boost::bind(&acceptor::handle_accept,
                         this,
                         boost::asio::placeholders::error)));
            }
            catch(exception& e)
            {
               cerr << "acceptor exception: " << e.what() << endl;
               return false;
            }

            return true;
         }

      private:

         void handle_accept(const boost::system::error_code& error)
         {
            if (!error)
            {
               session_->start(upstream_host_,upstream_port_);

               if (!accept_connections())
               {
                  cerr << "Failure during call to accept." << endl;
               }
            }
            else
            {
               cerr << "Error: " << error.message() << endl;
            }
         }

         boost::asio::io_context& io_context_;
         ip::address_v4 localhost_address;
         ip::tcp::acceptor acceptor_;
         ptr_type session_;
         unsigned short upstream_port_;
         string upstream_host_;
      };

   };
}
//gcc laproxy.cpp -o proxy -lboost_system -lpcre2-8 -lboost_thread -lstdc++
int main(int argc, char* argv[])
{
   if (argc < 5)
   {
      cerr << "usage: tcpproxy_server <local host ip> <local port> <forward host ip> <forward port>" << endl;
      return 1;
   }

   const unsigned short local_port   = static_cast<unsigned short>(::atoi(argv[2]));
   const unsigned short forward_port = static_cast<unsigned short>(::atoi(argv[4]));
   const string local_host      = argv[1];
   const string forward_host    = argv[3];

   boost::asio::io_context ios;

   regex_config.add("^(?s).{150,}$"); //      Avoid Big TCP packets
   regex_config.add("[^a-zA-Z0-9\\.,\\-_ ]{3,}"); //  Avoid Exploiting
   regex_config.add("(?i)(pineapple|ananas)"); //Who takes the pizza with pineapple?
   regex_config.add("https?:\\/\\/(?:www\\.)?youtube\\.com\\/.*watch.*\\?.*dQw4w9WgXcQ.*"); //Hell no, can't send a rickroll
   cerr << "Starting Proxy" << endl;
   try
   {
      tcp_proxy::bridge::acceptor acceptor(ios,
                                           local_host, local_port,
                                           forward_host, forward_port);

      acceptor.accept_connections();
      ios.run();

   }
   catch(exception& e)
   {
      cerr << "Error: " << e.what() << endl;
      return 1;
   }
   cerr << "Proxy stopped!" << endl;


   return 0;
}
