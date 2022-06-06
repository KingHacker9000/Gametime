from functools import wraps
from flask import session, redirect
from simpleDB import Database

class Logger():
    
    def __init__(self, name, mode):

        self.levels = ["INFO", "WARNING", "ERROR"]
        self.name = name
        self.level = 0
        if mode == "debug": self.level = 0
        elif mode == "n": self.level = 1
        elif mode == "runtime": self.level = 2
        elif mode == "dist": self.level == 3

    def log(self, text, l=0):
        if l >= self.level:
            statement = "("+ self.name + ") [" + self.levels[l]+ "] => " + text
            if l >= 2:
                print("="*len(statement))
                print(statement)
                print("="*len(statement))
            else:
                print(statement)
                

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("User_ID") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def error(errorCode, ErrorMessage):
    '''
    Return a Dictionary
    with the keys as Code and Message and Status
    '''
    d={'code': errorCode, 'message': str(ErrorMessage), 'status': 'Failed'}

    return d


if __name__ == '__main__':
    # Connect To Database
    db = Database("Database.db")
    
    db.execute("DROP TABLE IF EXISTS Organisations;")
    db.execute("DROP TABLE IF EXISTS Tournaments;")
    db.execute("DROP TABLE IF EXISTS Games;")
    db.execute("DROP TABLE IF EXISTS Teams;")
    db.execute("DROP TABLE IF EXISTS Players;")
    db.execute("DROP TABLE IF EXISTS Matches;")
    db.execute("DROP TABLE IF EXISTS Users;")
    db.execute("DROP TABLE IF EXISTS Scores;")

    db.execute("CREATE TABLE Organisations (Organisation_ID INTEGER PRIMARY KEY, Organisation_Name TEXT NOT NULL, Organisation_Code TEXT)")
    db.execute("CREATE TABLE Tournaments (Tournament_ID INTEGER PRIMARY KEY, Name Text NOT NULL, Organisation_ID INTEGER NOT NULL, Privacy TEXT NOT NULL, Details TEXT, Game_ID INTEGER NOT NULL, FOREIGN KEY (Organisation_ID) REFERENCES Organisations (Organisation_ID), FOREIGN KEY (Game_ID) REFERENCES Games (Game_ID))")
    db.execute("CREATE TABLE Games (Game_ID INTEGER PRIMARY KEY, Game_Type TEXT NOT NULL)")
    db.execute("CREATE TABLE Teams (Team_ID INTEGER PRIMARY KEY, Name TEXT NOT NULL, Game_ID INTEGER NOT NULL, Organisation_ID INTEGER NOT NULL, Tournament_ID INTEGER NOT NULL, Score INTEGER NOT NULL, Logo BLOB NOT NULL, FOREIGN KEY (Game_ID) REFERENCES Games (Game_ID), FOREIGN KEY (Organisation_ID) REFERENCES Organisations (Organisation_ID), FOREIGN KEY (Tournament_ID) REFERENCES Tournaments (Tournament_ID))")
    db.execute("CREATE TABLE Players (Player_ID INTEGER PRIMARY KEY, Name TEXT, Details TEXT, Team_ID INTEGER, FOREIGN KEY (Team_ID) REFERENCES Teams (Team_ID))")
    db.execute("CREATE TABLE Matches (Match_ID INTEGER PRIMARY KEY, Tournament_ID INTEGER, Team_One_ID INTEGER, Team_Two_ID INTEGER, Game_ID INTEGER, Result TEXT, Score TEXT, Description TEXT, Time INTEGER, FOREIGN KEY (Team_One_ID) REFERENCES Teams (Team_ID), FOREIGN KEY (Team_Two_ID) REFERENCES Teams (Team_ID), FOREIGN KEY (Game_ID) REFERENCES Games (Game_ID), FOREIGN KEY (Tournament_ID) REFERENCES Tournaments (Tournament_ID))")
    db.execute("CREATE TABLE Users (User_ID INTEGER PRIMARY KEY, Username TEXT NOT NULL, User_Password TEXT NOT NULL, Organisation_ID INTEGER, FOREIGN KEY (Organisation_ID) REFERENCES Organisations (Organisation_ID))")
    db.execute("CREATE TABLE Scores (Score_ID INTEGER PRIMARY KEY, Team_ID INTEGER NOT NULL, Tournament_ID INTEGER, Score TEXT, FOREIGN KEY (Team_ID) REFERENCES Teams (Team_ID), FOREIGN KEY (Tournament_ID) REFERENCES Tournaments (Tournament_ID))")
    
    Games = ["Football/Soccer", "Cricket", "Basketball", "Baseball", "Swimming", "Track & Field", "Kho-Kho", "Badminton"]
    Games.sort()

    for game in Games:
        db.execute("INSERT INTO Games (Game_Type) VALUES (?)", (game,))




    print(db.execute("SELECT * FROM Organisations"))
    print(db.execute("SELECT * FROM Tournaments"))
    print(db.execute("SELECT * FROM Games"))
    #print(db.execute("SELECT * FROM Teams"))
    print(db.execute("SELECT * FROM Players"))
    print(db.execute("SELECT * FROM Matches"))
    print(db.execute("SELECT * FROM Users"))
    print(db.execute("SELECT * FROM Scores"))




