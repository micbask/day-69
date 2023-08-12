import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, mapped_column
from sqlalchemy import ForeignKey
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
Bootstrap5(app)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
db = SQLAlchemy()
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(code=403)
        return f(*args, **kwargs)

    return decorated_function


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = mapped_column(db.Integer, primary_key=True)
    author_id = mapped_column(db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = mapped_column(db.Integer, primary_key=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")
    name = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    hashed_password = db.Column(db.String(30), unique=True, nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = mapped_column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    author_id = mapped_column(db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    post_id = mapped_column(db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")
    date = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User()
        new_user.name = form.name.data
        new_user.email = form.email.data
        new_user.hashed_password = generate_password_hash(password=str(form.password.data), method='pbkdf2:sha256',
                                                          salt_length=8)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    logout_user()
    form = LoginForm()
    if form.validate_on_submit():
        if form.email.data in [user.email for user in db.session.execute(db.select(User)).scalars().all()]:
            user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
            if check_password_hash(pwhash=user.hashed_password, password=str(form.password.data)):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect Password")
        else:
            flash("Email Not Found")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    comments = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars().all()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(author=current_user,
                                  author_id=current_user.id,
                                  text=form.commentbox.data,
                                  post_id=post_id,
                                  post=db.session.get(BlogPost, post_id),
                                  date=date.today().strftime("%B %d, %Y"))
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need to log in.")
            return redirect(url_for("login"))
    return render_template("post.html",
                           post=requested_post,
                           comment_form=form,
                           comments=comments,
                           gravatar=Gravatar(app,
                                             size=100,
                                             rating='g',
                                             default='retro',
                                             force_default=False,
                                             force_lower=False,
                                             use_ssl=False,
                                             base_url=None))


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(title=form.title.data,
                            subtitle=form.subtitle.data,
                            body=form.body.data,
                            img_url=form.img_url.data,
                            author=current_user,
                            date=date.today().strftime("%B %d, %Y"))
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", endpoint="edit_post", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(title=post.title,
                               subtitle=post.subtitle,
                               img_url=post.img_url,
                               author=post.author,
                               body=post.body)
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>", endpoint="delete_post")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
