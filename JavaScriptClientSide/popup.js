console.log("client side script");

sessionChoice();

function sessionChoice(){
  if(confirm("You currently are running another session - press OK to terminate this other session and login now, or press cancel")){
    document.getElementById("output").value = "login";
    document.getElementById("loginButton_0").click();
  }else{
    document.getElementById("output").value = "cancel";
    document.getElementById("loginButton_0").click();
  }
}
