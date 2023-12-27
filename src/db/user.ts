import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  resume: {
    summary: {
      type: String,
      default: "",
    },
    education: [
      {
        institution: String,
        degree: String,
        startDate: Date,
        endDate: Date,
      },
    ],
    experience: [
      {
        company: String,
        position: String,
        startDate: Date,
        endDate: Date,
        description: String,
      },
    ],
    skills: [String],
    projects: [
      {
        title: String,
        description: String,
        url: String,
      },
    ],
  },
  authentication: {
    password: { type: String, required: true, select: false },
    salt: { type: String, select: false },
    sessionToken: { type: String, select: false },
  },
});

export const UserModel = mongoose.model("user", UserSchema);

export const getUsers = () => UserModel.find();
export const getUserByEmail = (email: string) => UserModel.findOne({ email });
export const getUserBySessionToken = (sessionToken: string) =>
  UserModel.findOne({ "authentication.sessionToken": sessionToken });

export const getUserById = (id: string) => UserModel.findById(id);

export const createUser = (values: Record<string, any>) =>
  new UserModel(values).save().then((user) => user.toObject());

export const deleteUserById = (id: string) =>
  UserModel.findByIdAndDelete({ _id: id });

export const updateUserById = (id: string, values: Record<string, any>) =>
  UserModel.findByIdAndUpdate(id, values);
