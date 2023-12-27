import { authentication } from "./../helpers/index";
import { createUser, getUserByEmail } from "../db/user";
import express from "express";
import { random } from "../helpers";

export const register = async (req: express.Request, res: express.Response) => {
  try {
    const { email, password, username, lastName, firstName } = req.body;

    if (!email || !password || !username) {
      return res.sendStatus(400);
    }

    const existingEmail = await getUserByEmail(email);

    if (existingEmail) {
      return res.sendStatus(400);
    }

    const salt = random();

    const user = await createUser({
      email,
      username,
      lastName,
      firstName,
      authentication: {
        salt,
        password: authentication(salt, password),
      },
    });

    return res.status(200).json(user).end();
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};

export const login = async (req: express.Request, res: express.Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.sendStatus(400);
    }

    const user = await getUserByEmail(email).select(
      "+authentication.salt +authentication.password"
    );

    if (!user) {
      return res.sendStatus(400);
    }

    const expectedHash = authentication(user.authentication.salt, password);

    if (user.authentication.password !== expectedHash) {
      return res.sendStatus(403);
    }

    const salt = random();
    user.authentication.sessionToken = authentication(
      salt,
      user._id.toString()
    );

    await user.save();

    res.cookie("RESTFUL-API-AUTH", user.authentication.sessionToken, {
      domain: "localhost",
    });

    return res.status(200).json(user).end();
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};
