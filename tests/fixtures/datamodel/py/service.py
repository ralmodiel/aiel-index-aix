from models import Account


def rename(session, email):
    acc = session.query(Account).filter_by(email=email).first()
    session.execute("UPDATE owners SET name = 'x' WHERE id = 1")
    return acc
